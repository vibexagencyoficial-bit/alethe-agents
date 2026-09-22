//! Control Plane local do Alethe para integração real com o Transcripts.
//!
//! O listener usa somente loopback. Health/version/capabilities e o pareamento são públicos;
//! qualquer operação que possa criar processos, escrever arquivos ou alterar Git exige um token
//! Bearer emitido no pareamento. Os hashes das sessões ficam no Credential Manager/Keyring do SO.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use tiny_http::{Header, Request, Response, StatusCode};

const PREFIX: &str = "/control/v1";
const MAX_BODY: usize = 64 * 1024;
const PAIRING_WINDOW: Duration = Duration::from_secs(120);
/// Tauri event the window listens on to open the consent prompt.
pub const PAIRING_REQUESTED_EVENT: &str = "control://pairing/requested";
const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const CREDENTIAL_SERVICE: &str = "com.kc1t.alethe.control-plane";
const LEGACY_CREDENTIAL_USER: &str = "sessions";
const SESSION_INDEX_PREFIX: &str = "sessions-index-";
const SESSION_CREDENTIAL_PREFIX: &str = "session-";
const SESSION_INDEX_SHARDS: &str = "0123456789abcdef";

static INSTANCE_ID: OnceLock<String> = OnceLock::new();
static STATE: OnceLock<ControlState> = OnceLock::new();
static EVENT_SUBSCRIBERS: OnceLock<Mutex<Vec<Sender<String>>>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize)]
struct PairingStartInput {
    client_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PairingCompleteInput {
    client_id: String,
    pairing_code: String,
}

#[derive(Debug, Deserialize)]
struct TerminalStartInput {
    cols: Option<u16>,
    rows: Option<u16>,
    id: Option<String>,
    command: Option<String>,
    cwd: Option<String>,
    extra_args: Option<Vec<String>>,
    launcher_override: Option<String>,
    env: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct TerminalInput {
    data: String,
}

#[derive(Debug, Deserialize)]
struct AgentSpawnInput {
    agent: String,
    task: Option<String>,
    id: Option<String>,
    cwd: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
    extra_args: Option<Vec<String>>,
    launcher_override: Option<String>,
    env: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct AgentMessageInput {
    message: Option<String>,
    data: Option<String>,
}

/// Corpo da rota de prova. `dir` é opcional: sem ele o app cria uma pasta temporária própria. O
/// chamador NÃO manda args nem prompts — quem dirige a prova é o app (ver `run_runtime_proof`).
#[derive(Debug, Deserialize)]
struct RuntimeProofInput {
    #[serde(default)]
    dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FilesystemPathInput {
    path: String,
}

#[derive(Debug, Deserialize)]
struct FilesystemWriteInput {
    path: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct FilesystemMoveInput {
    path: String,
    destination: String,
}

#[derive(Debug, Deserialize)]
struct GitInitInput {
    path: String,
}

#[derive(Debug, Deserialize)]
struct GitPathsInput {
    repo_root: String,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GitDiscardInput {
    repo_root: String,
    paths: Vec<String>,
    untracked: bool,
}

#[derive(Debug, Deserialize)]
struct GitCommitInput {
    repo_root: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct GitBranchInput {
    repo: String,
    hash: String,
    branch_name: String,
}

#[derive(Debug, Deserialize)]
struct GitHashInput {
    repo: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct GitResetInput {
    repo: String,
    hash: String,
    mode: String,
}

#[derive(Debug, Deserialize)]
struct WorktreeProvisionInput {
    repo: String,
    agent_id: String,
    mode: crate::worktrees::WorktreeMode,
}

#[derive(Debug, Deserialize)]
struct WorktreeAgentInput {
    repo: String,
    agent_id: String,
}

#[derive(Debug, Deserialize)]
struct WorktreeLockInput {
    repo: String,
    agent_id: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorktreeCommitInput {
    repo: String,
    agent_id: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ValidationInput {
    cwd: String,
    commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSession {
    client_id: String,
    token_hash: String,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairingStatus {
    Pending,
    Approved,
    Denied,
}

impl PairingStatus {
    fn as_str(self) -> &'static str {
        match self {
            PairingStatus::Pending => "pending",
            PairingStatus::Approved => "approved",
            PairingStatus::Denied => "denied",
        }
    }
}

#[derive(Clone, Debug)]
struct PairingChallenge {
    client_id: String,
    code: String,
    expires_at: SystemTime,
    requested_at: SystemTime,
    status: PairingStatus,
}

struct ControlState {
    pairing: Mutex<Option<PairingChallenge>>,
    sessions: Mutex<Vec<StoredSession>>,
    storage_error: Mutex<Option<String>>,
}

fn instance_id() -> &'static str {
    INSTANCE_ID.get_or_init(|| nanoid::nanoid!(21))
}

fn state() -> &'static ControlState {
    STATE.get_or_init(ControlState::new)
}

fn event_subscribers() -> &'static Mutex<Vec<Sender<String>>> {
    EVENT_SUBSCRIBERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn sse_frame(event: &str, payload: &Value) -> String {
    format!("event: {event}\ndata: {}\n\n", payload)
}

pub fn publish_event(event: &str, payload: &Value) {
    let frame = sse_frame(event, payload);
    let Ok(mut subscribers) = event_subscribers().lock() else {
        return;
    };
    subscribers.retain(|subscriber| subscriber.send(frame.clone()).is_ok());
}

fn subscribe_events() -> Receiver<String> {
    ensure_bus_bridge();
    let (sender, receiver) = mpsc::channel();
    if let Ok(mut subscribers) = event_subscribers().lock() {
        subscribers.push(sender);
    }
    receiver
}

/// Tipos de evento que podem sair pelo `/control/v1/events`. O bus é compartilhado com a interface
/// (scheduler, supervisor, planejamento, merge, gráficos) e vários desses eventos levam texto do
/// usuário no payload — `task_title` no `AgentSpawnRequested`, `subject` no `PlanningCommitted`,
/// `error`/`reason` nos `TaskFailed`. O stream é a fronteira do control plane e o consumidor
/// persiste o que recebe, então o que não está nesta lista não atravessa: um evento novo no bus não
/// vaza por descuido, só entra aqui por decisão. Os eventos desta lista ainda passam pelo guarda de
/// conteúdo do `emit_control_event`.
const SSE_PUBLISHED_EVENTS: &[&str] = &[
    "agent.started",
    "agent.working",
    "agent.completed",
    "agent.failed",
    "agent.stopped",
    "terminal.output",
    "file.changed",
    "git.changed",
    "worktree.created",
    "worktree.removed",
    "validation.started",
    "validation.completed",
    // já saíam pelo stream antes desta task: o anúncio do pareamento (Task 1) e o `agent.started`
    "pairing.decided",
    // diagnóstico da ponte: sem isso o consumidor não sabe que perdeu evento nem que a ponte caiu
    "bus.lagged",
    "bus.bridge_unavailable",
];

/// Ponte event bus → SSE. O bus é a fonte única do ciclo de vida (scheduler, supervisor, rotas do
/// control plane, pty) e o `/control/v1/events` é o consumidor externo; sem a ponte o stream nasce
/// quase vazio, que era o defeito desta task. Idempotente: a primeira assinatura liga. Só o que
/// está em `SSE_PUBLISHED_EVENTS` atravessa — o resto do bus morre aqui.
fn ensure_bus_bridge() {
    static BRIDGE: OnceLock<()> = OnceLock::new();
    if BRIDGE.set(()).is_err() {
        return;
    }
    // Assinar ANTES de subir a thread: o broadcast só entrega para quem já era assinante no
    // momento do envio, então um evento publicado antes de a thread ser escalonada (o que
    // acontece sob carga) se perderia para sempre.
    let mut receiver = crate::event_bus::subscribe();
    let spawned = std::thread::Builder::new()
        .name("alethe-bus-bridge".to_string())
        .spawn(move || loop {
            match receiver.blocking_recv() {
                Ok(payload) => {
                    if SSE_PUBLISHED_EVENTS.contains(&payload.event_type.as_str()) {
                        publish_event(&payload.event_type, &bus_envelope(&payload));
                    }
                }
                // Perder eventos por lentidão não pode derrubar a ponte: o consumidor recebe um
                // aviso com o tamanho do salto e o stream continua vivo.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    publish_event("bus.lagged", &json!({ "skipped": skipped }));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        });
    if let Err(error) = spawned {
        // O consumidor precisa saber que a ponte não subiu; sem isso ele esperaria para sempre num
        // stream que só entrega `ready` e keep-alive. O OnceLock fica marcado de propósito: duas
        // pontes ao mesmo tempo entregariam cada evento duplicado no SSE.
        eprintln!("[event-bus] ponte para o SSE não subiu: {error}");
        publish_event("bus.bridge_unavailable", &json!({ "error": error.to_string() }));
    }
}

/// Envelope que vai no `data:` do frame SSE. O `event:` já carrega o tipo, então ele não se repete
/// aqui; o resto do envelope vai inteiro para o consumidor filtrar por agente/correlação.
fn bus_envelope(payload: &crate::event_bus::EventBusPayload) -> Value {
    json!({
        "timestamp_ms": payload.timestamp_ms,
        "correlation_id": payload.correlation_id,
        "task_id": payload.task_id,
        "agent_id": payload.agent_id,
        "data": payload.data,
    })
}

fn stream_events(mut writer: Box<dyn Write + Send + 'static>, receiver: Receiver<String>) {
    let header = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    if writer.write_all(header).and_then(|_| writer.flush()).is_err() {
        return;
    }
    let ready = sse_frame(
        "ready",
        &json!({ "service": "alethe-control", "instance_id": instance_id() }),
    );
    if writer
        .write_all(ready.as_bytes())
        .and_then(|_| writer.flush())
        .is_err()
    {
        return;
    }
    loop {
        match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(frame) => {
                if writer
                    .write_all(frame.as_bytes())
                    .and_then(|_| writer.flush())
                    .is_err()
                {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if writer.write_all(b": keep-alive\n\n").and_then(|_| writer.flush()).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// GET /control/v1/events: stream SSE dos eventos de ciclo de vida. `pub(crate)` para o teste
/// abrir um stream real sem montar um AppHandle. Devolve o request de volta quando a rota não é
/// esta (`Some(request)`); `None` significa request consumido — pela resposta 401 ou pelo stream.
pub(crate) fn events_route(method: &str, path: &str, request: Request) -> Option<Request> {
    if method != "GET" || path != "/control/v1/events" {
        return Some(request);
    }
    let Some(token) = bearer_token(&request) else {
        let _ = request.respond(unauthorized_response());
        return None;
    };
    if state().authenticate(token).is_err() {
        let _ = request.respond(unauthorized_response());
        return None;
    }
    let receiver = subscribe_events();
    let writer = request.into_writer();
    std::thread::spawn(move || stream_events(writer, receiver));
    None
}

/// Chaves de conteúdo livre barradas nos eventos do control plane. O consumidor persiste e
/// retransmite cada evento (outbox do lado Go), então texto de usuário, linha de comando ou saída
/// de execução viraria conteúdo de terceiro gravado em tabela — token em header, dump de ambiente,
/// log de teste. A comparação é exata sobre a chave em minúsculas (por isso `message_bytes` passa e
/// `message` não) e desce em objetos e arrays aninhados.
const FORBIDDEN_EVENT_KEYS: &[&str] = &[
    "body", "command", "commands", "content", "data", "input", "message", "output", "password",
    "prompt", "secret", "stderr", "stdout", "text", "token",
];

fn forbidden_event_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => object.iter().find_map(|(key, nested)| {
            if FORBIDDEN_EVENT_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                Some(key.clone())
            } else {
                forbidden_event_key(nested)
            }
        }),
        Value::Array(items) => items.iter().find_map(forbidden_event_key),
        _ => None,
    }
}

/// Fonte única dos eventos de ciclo de vida do control plane: publica no event bus (tokio
/// broadcast), que alimenta o webview e — pela ponte — o stream SSE. O SSE não recebe evento por
/// outro caminho, para não existirem duas ordens de entrega para o mesmo ciclo de vida.
///
/// É a porta única, e por isso o ciclo de vida do PTY também entra por aqui em vez de chamar o bus
/// direto: quem passa por esta função passa pelo guarda de conteúdo.
pub(crate) fn emit_control_event(event_type: &str, agent_id: Option<String>, payload: Value) {
    if let Some(key) = forbidden_event_key(&payload) {
        // Falha fechada e barulhenta: o evento não sai e o motivo fica no stderr do app. Um emissor
        // novo que tente mandar conteúdo quebra no teste, não em produção.
        eprintln!("[event-bus] evento {event_type} recusado: payload carrega conteúdo ('{key}')");
        return;
    }
    crate::event_bus::publish_event_simple(
        event_type,
        &format!("ctrl-{}", nanoid::nanoid!(12)),
        None,
        agent_id,
        payload,
    );
}

/// O que mudou no disco, não o que foi escrito nele: `action` + `path` (+ `destination` no move). O
/// evento é persistido pelo consumidor, então conteúdo de arquivo do usuário fica de fora.
fn emit_file_changed(action: &str, path: String, destination: Option<String>) {
    let mut payload = json!({ "action": action, "path": path });
    if let Some(destination) = destination {
        payload["destination"] = Value::String(destination);
    }
    emit_control_event("file.changed", None, payload);
}

/// O que a rota fez no repositório: `action` + `repo` (o caminho que a rota usou), mais `path_count`
/// em quem recebeu caminhos e `mode` no reset. Ficam de fora a mensagem de commit e a saída do git
/// (pull/push/commit devolvem stdout ao chamador, mas o evento é persistido pelo consumidor) — e por
/// isso não vai a lista de caminhos, só quantos foram: um `stage` de mil arquivos não pode inflar o
/// evento guardado. Quem quiser o detalhe pede `git status`/`git diff`.
///
/// `repo` vai como a rota recebeu, exceto no `init`, que canonicaliza (é o root que o git devolve) —
/// por isso lá o prefixo verbatim do Windows é removido, e não nos outros.
fn emit_git_changed(action: &str, repo: String, extra: &[(&str, Value)]) {
    let mut payload = json!({ "action": action, "repo": repo });
    for (key, value) in extra {
        payload[key] = value.clone();
    }
    emit_control_event("git.changed", None, payload);
}

impl ControlState {
    fn new() -> Self {
        match load_sessions() {
            Ok(sessions) => Self {
                pairing: Mutex::new(None),
                sessions: Mutex::new(sessions),
                storage_error: Mutex::new(None),
            },
            Err(error) => Self {
                pairing: Mutex::new(None),
                sessions: Mutex::new(Vec::new()),
                storage_error: Mutex::new(Some(error)),
            },
        }
    }

    fn storage_ready(&self) -> Result<(), String> {
        let error = self
            .storage_error
            .lock()
            .map_err(|_| "credential_store_lock_failed".to_string())?;
        match error.as_ref() {
            Some(error) => Err(format!("credential_store_unavailable: {error}")),
            None => Ok(()),
        }
    }

    fn start_pairing(&self, client_id: String) -> Result<Value, String> {
        let client_id = valid_client_id(&client_id)?;
        self.storage_ready()?;
        let now = SystemTime::now();
        let expires_at = now + PAIRING_WINDOW;
        let challenge = PairingChallenge {
            client_id: client_id.clone(),
            code: nanoid::nanoid!(32),
            expires_at,
            requested_at: now,
            status: PairingStatus::Pending,
        };
        self.pairing
            .lock()
            .map_err(|_| "pairing_lock_failed".to_string())?
            .replace(challenge);
        Ok(json!({
            "client_id": client_id,
            "approval_required": true,
            "expires_at": unix_seconds(expires_at),
            "expires_in_seconds": PAIRING_WINDOW.as_secs(),
            "one_time": true
        }))
    }

    /// The pairing code only ever leaves through this call, which the Alethe window reaches over
    /// Tauri IPC. It is deliberately absent from every HTTP response: a client that could read its
    /// own code would be approving itself.
    fn pairing_pending(&self) -> Result<Value, String> {
        let mut pairing = self
            .pairing
            .lock()
            .map_err(|_| "pairing_lock_failed".to_string())?;
        let Some(challenge) = pairing.as_ref() else {
            return Ok(json!({ "pending": false }));
        };
        if challenge.expires_at <= SystemTime::now() {
            pairing.take();
            return Ok(json!({ "pending": false, "expired": true }));
        }
        Ok(json!({
            "pending": true,
            "client_id": challenge.client_id,
            "code": challenge.code,
            "status": challenge.status.as_str(),
            "requested_at": unix_seconds(challenge.requested_at),
            "expires_at": unix_seconds(challenge.expires_at),
            "expires_in_seconds": challenge
                .expires_at
                .duration_since(SystemTime::now())
                .unwrap_or_default()
                .as_secs()
        }))
    }

    fn pairing_decide(&self, approve: bool) -> Result<Value, String> {
        let mut pairing = self
            .pairing
            .lock()
            .map_err(|_| "pairing_lock_failed".to_string())?;
        let challenge = pairing
            .as_mut()
            .ok_or_else(|| "pairing_not_started".to_string())?;
        if challenge.expires_at <= SystemTime::now() {
            pairing.take();
            return Err("pairing_expired".to_string());
        }
        challenge.status = if approve {
            PairingStatus::Approved
        } else {
            PairingStatus::Denied
        };
        let client_id = challenge.client_id.clone();
        let status = challenge.status.as_str();
        drop(pairing);
        emit_control_event(
            "pairing.decided",
            None,
            json!({ "client_id": client_id, "approved": approve, "status": status }),
        );
        Ok(json!({ "client_id": client_id, "status": status, "approved": approve }))
    }

    fn complete_pairing(&self, input: PairingCompleteInput) -> Result<Value, String> {
        let client_id = valid_client_id(&input.client_id)?;
        if input.pairing_code.trim().is_empty() {
            return Err("pairing_code_required".to_string());
        }
        self.storage_ready()?;
        let challenge = self
            .pairing
            .lock()
            .map_err(|_| "pairing_lock_failed".to_string())?
            .clone()
            .ok_or_else(|| "pairing_not_started".to_string())?;
        if challenge.expires_at <= SystemTime::now() {
            let _ = self.pairing.lock().map(|mut pairing| pairing.take());
            return Err("pairing_expired".to_string());
        }
        if challenge.status == PairingStatus::Denied {
            return Err("pairing_denied".to_string());
        }
        if challenge.status != PairingStatus::Approved {
            return Err("pairing_approval_pending".to_string());
        }
        if challenge.client_id != client_id
            || !constant_time_equal(&challenge.code, input.pairing_code.trim())
        {
            return Err("invalid_pairing_code".to_string());
        }

        let token = nanoid::nanoid!(48);
        let now = SystemTime::now();
        let session = StoredSession {
            client_id: client_id.clone(),
            token_hash: token_hash(&token),
            created_at: unix_seconds(now),
            expires_at: unix_seconds(now + SESSION_LIFETIME),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session_lock_failed".to_string())?;
        let mut next = sessions.clone();
        next.retain(|entry| entry.expires_at > unix_seconds(now));
        next.push(session.clone());
        persist_sessions(&next)?;
        *sessions = next;
        drop(sessions);
        self.pairing
            .lock()
            .map_err(|_| "pairing_lock_failed".to_string())?
            .take();
        Ok(json!({
            "client_id": client_id,
            "access_token": token,
            "token_type": "Bearer",
            "created_at": session.created_at,
            "expires_at": session.expires_at
        }))
    }

    fn authenticate(&self, token: &str) -> Result<StoredSession, String> {
        self.storage_ready()?;
        let hash = token_hash(token);
        let now = unix_seconds(SystemTime::now());
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session_lock_failed".to_string())?;
        if sessions.iter().any(|session| session.expires_at <= now) {
            sessions.retain(|session| session.expires_at > now);
            persist_sessions(&sessions)?;
        }
        sessions
            .iter()
            .find(|session| constant_time_equal(&session.token_hash, &hash))
            .cloned()
            .ok_or_else(|| "invalid_access_token".to_string())
    }

    fn rotate(&self, token: &str) -> Result<Value, String> {
        let current = self.authenticate(token)?;
        let replacement_token = nanoid::nanoid!(48);
        let now = SystemTime::now();
        let replacement = StoredSession {
            client_id: current.client_id.clone(),
            token_hash: token_hash(&replacement_token),
            created_at: unix_seconds(now),
            expires_at: unix_seconds(now + SESSION_LIFETIME),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session_lock_failed".to_string())?;
        let mut next = sessions.clone();
        next.retain(|session| session.token_hash != current.token_hash);
        next.push(replacement.clone());
        persist_sessions(&next)?;
        *sessions = next;
        Ok(json!({
            "client_id": replacement.client_id,
            "access_token": replacement_token,
            "token_type": "Bearer",
            "created_at": replacement.created_at,
            "expires_at": replacement.expires_at
        }))
    }

    fn revoke(&self, token: &str) -> Result<Value, String> {
        let current = self.authenticate(token)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "session_lock_failed".to_string())?;
        let next = sessions
            .iter()
            .filter(|session| session.token_hash != current.token_hash)
            .cloned()
            .collect::<Vec<_>>();
        persist_sessions(&next)?;
        *sessions = next;
        Ok(json!({ "revoked": true, "client_id": current.client_id }))
    }
}

fn keyring_entry(user: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(CREDENTIAL_SERVICE, user)
        .map_err(|error| format!("credential_entry_unavailable: {error}"))
}

fn session_entry(token_hash: &str) -> Result<keyring::Entry, String> {
    keyring_entry(&format!("{SESSION_CREDENTIAL_PREFIX}{token_hash}"))
}

fn session_index_entry(shard: char) -> Result<keyring::Entry, String> {
    keyring_entry(&format!("{SESSION_INDEX_PREFIX}{shard}"))
}

fn session_index_shard(token_hash: &str) -> char {
    token_hash.chars().next().unwrap_or('0')
}

fn load_index_hashes() -> Result<Vec<String>, String> {
    let mut hashes = Vec::new();
    for shard in SESSION_INDEX_SHARDS.chars() {
        match session_index_entry(shard)?.get_password() {
            Ok(value) => {
                for hash in value.lines().map(str::trim).filter(|hash| !hash.is_empty()) {
                    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err("credential_index_invalid".to_string());
                    }
                    if !hashes.iter().any(|existing| existing == hash) {
                        hashes.push(hash.to_string());
                    }
                }
            }
            Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(format!("credential_index_read_failed: {error}")),
        }
    }
    Ok(hashes)
}

fn load_sessions() -> Result<Vec<StoredSession>, String> {
    let hashes = load_index_hashes()?;
    if !hashes.is_empty() {
        return hashes
            .into_iter()
            .map(|hash| {
                let serialized = session_entry(&hash)?.get_password().map_err(|error| match error {
                    keyring::Error::NoEntry => "credential_session_missing".to_string(),
                    other => format!("credential_session_read_failed: {other}"),
                })?;
                let session: StoredSession = serde_json::from_str(&serialized)
                    .map_err(|error| format!("credential_session_data_invalid: {error}"))?;
                if session.token_hash != hash {
                    return Err("credential_session_hash_mismatch".to_string());
                }
                Ok(session)
            })
            .collect();
    }

    match keyring_entry(LEGACY_CREDENTIAL_USER)?.get_password() {
        Ok(serialized) => serde_json::from_str(&serialized)
            .map_err(|error| format!("credential_data_invalid: {error}")),
        Err(keyring::Error::NoEntry) => Ok(Vec::new()),
        Err(error) => Err(format!("credential_read_failed: {error}")),
    }
}

fn persist_sessions(sessions: &[StoredSession]) -> Result<(), String> {
    let previous_hashes = load_index_hashes()?;
    let desired_hashes: HashSet<&str> = sessions.iter().map(|s| s.token_hash.as_str()).collect();
    for session in sessions {
        let serialized = serde_json::to_string(session)
            .map_err(|error| format!("credential_session_data_encode_failed: {error}"))?;
        session_entry(&session.token_hash)?
            .set_password(&serialized)
            .map_err(|error| format!("credential_session_write_failed: {error}"))?;
    }
    for shard in SESSION_INDEX_SHARDS.chars() {
        let value = sessions
            .iter()
            .filter(|session| session_index_shard(&session.token_hash) == shard)
            .map(|session| session.token_hash.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let entry = session_index_entry(shard)?;
        if value.is_empty() {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(format!("credential_index_delete_failed: {error}")),
            }
        } else {
            entry
                .set_password(&value)
                .map_err(|error| format!("credential_index_write_failed: {error}"))?;
        }
    }
    for hash in previous_hashes {
        if !desired_hashes.contains(hash.as_str()) {
            match session_entry(&hash)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(format!("credential_session_delete_failed: {error}")),
            }
        }
    }
    match keyring_entry(LEGACY_CREDENTIAL_USER)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("credential_legacy_delete_failed: {error}")),
    }
}

fn valid_client_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("client_id_required".to_string());
    }
    if value.len() > 128 {
        return Err("client_id_too_long".to_string());
    }
    Ok(value.to_string())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = (left.len() ^ right.len()) as u8;
    for index in 0..left.len().max(right.len()) {
        difference |= left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn json_response(status: u16, payload: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8")
        .expect("static control-plane header");
    Response::from_string(payload.to_string())
        .with_status_code(StatusCode(status))
        .with_header(header)
}

fn error_response(status: u16, error: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, json!({ "error": error }))
}

fn endpoint_path(url: &str) -> &str {
    url.split_once('?').map(|(path, _)| path).unwrap_or(url)
}

pub fn is_control_path(url: &str) -> bool {
    let path = endpoint_path(url);
    path == PREFIX || path.starts_with("/control/v1/")
}

fn query_parameter(url: &str, key: &str) -> Option<String> {
    url.split_once('?')?.1.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name != key {
            return None;
        }
        urlencoding::decode(value).ok().map(|decoded| decoded.into_owned())
    })
}

fn read_json<T: DeserializeOwned>(request: &mut Request) -> Result<T, String> {
    let mut body = Vec::new();
    request
        .as_reader()
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| "request_body_read_failed".to_string())?;
    if body.len() > MAX_BODY {
        return Err("request_body_too_large".to_string());
    }
    serde_json::from_slice(&body).map_err(|_| "invalid_json_body".to_string())
}

/// `pub(crate)` porque o teste de concorrência do listener (`agent_events`) responde o payload
/// real do `/health` em vez de um JSON de mentira.
pub(crate) fn health(port: u16) -> Value {
    json!({
        "service": "alethe-control",
        "version": "1",
        "ready": true,
        "instance_id": instance_id(),
        "bind": "127.0.0.1",
        "port": port
    })
}

fn version() -> Value {
    json!({
        "service": "alethe-control",
        "protocol": "1",
        "application": env!("CARGO_PKG_VERSION"),
        "instance_id": instance_id()
    })
}

fn capabilities() -> Value {
    json!({
        "service": "alethe-control",
        "protocol": "1",
        "authenticated": true,
        "read_only": false,
        "public_endpoints": [
            { "method": "GET", "path": "/control/v1/health" },
            { "method": "GET", "path": "/control/v1/version" },
            { "method": "GET", "path": "/control/v1/capabilities" },
            { "method": "POST", "path": "/control/v1/pairing/start" },
            { "method": "POST", "path": "/control/v1/pairing/complete" }
        ],
        "authenticated_endpoints": [
            { "method": "GET", "path": "/control/v1/runtime" },
            { "method": "GET", "path": "/control/v1/agents" },
            { "method": "POST", "path": "/control/v1/runtimes/{id}/proof" },
            { "method": "POST", "path": "/control/v1/agents/spawn" },
            { "method": "GET", "path": "/control/v1/agents/{id}" },
            { "method": "POST", "path": "/control/v1/agents/{id}/send" },
            { "method": "POST", "path": "/control/v1/agents/{id}/steer" },
            { "method": "POST", "path": "/control/v1/agents/{id}/interrupt" },
            { "method": "POST", "path": "/control/v1/agents/{id}/stop" },
            { "method": "GET", "path": "/control/v1/agents/{id}/status" },
            { "method": "GET", "path": "/control/v1/agents/{id}/output" },
            { "method": "GET", "path": "/control/v1/projects" },
            { "method": "GET", "path": "/control/v1/projects/{id}" },
            { "method": "GET", "path": "/control/v1/targets" },
            { "method": "GET", "path": "/control/v1/targets/{id}" },
            { "method": "POST", "path": "/control/v1/terminals" },
            { "method": "GET", "path": "/control/v1/terminals" },
            { "method": "GET", "path": "/control/v1/terminals/{id}" },
            { "method": "POST", "path": "/control/v1/terminals/{id}/input" },
            { "method": "GET", "path": "/control/v1/terminals/{id}/scrollback" },
            { "method": "POST", "path": "/control/v1/terminals/{id}/interrupt" },
            { "method": "POST", "path": "/control/v1/terminals/{id}/restart" },
            { "method": "DELETE", "path": "/control/v1/terminals/{id}" },
            { "method": "GET", "path": "/control/v1/fs/list" },
            { "method": "GET", "path": "/control/v1/fs/read" },
            { "method": "PUT", "path": "/control/v1/fs/write" },
            { "method": "POST", "path": "/control/v1/fs/mkdir" },
            { "method": "POST", "path": "/control/v1/fs/move" },
            { "method": "DELETE", "path": "/control/v1/fs" },
            { "method": "GET", "path": "/control/v1/git/status" },
            { "method": "GET", "path": "/control/v1/git/diff" },
            { "method": "GET", "path": "/control/v1/git/log" },
            { "method": "GET", "path": "/control/v1/git/branches" },
            { "method": "GET", "path": "/control/v1/git/incoming-outgoing" },
            { "method": "POST", "path": "/control/v1/git/init" },
            { "method": "POST", "path": "/control/v1/git/stage" },
            { "method": "POST", "path": "/control/v1/git/unstage" },
            { "method": "POST", "path": "/control/v1/git/discard" },
            { "method": "POST", "path": "/control/v1/git/commit" },
            { "method": "POST", "path": "/control/v1/git/pull" },
            { "method": "POST", "path": "/control/v1/git/push" },
            { "method": "POST", "path": "/control/v1/git/branch" },
            { "method": "POST", "path": "/control/v1/git/cherry-pick" },
            { "method": "POST", "path": "/control/v1/git/revert" },
            { "method": "POST", "path": "/control/v1/git/reset" },
            { "method": "GET", "path": "/control/v1/worktrees" },
            { "method": "POST", "path": "/control/v1/worktrees" },
            { "method": "DELETE", "path": "/control/v1/worktrees/{agent}" },
            { "method": "GET", "path": "/control/v1/worktrees/{agent}/changes" },
            { "method": "POST", "path": "/control/v1/worktrees/{agent}/lock" },
            { "method": "POST", "path": "/control/v1/worktrees/{agent}/unlock" },
            { "method": "POST", "path": "/control/v1/worktrees/{agent}/fetch" },
            { "method": "POST", "path": "/control/v1/worktrees/{agent}/commit" },
            { "method": "POST", "path": "/control/v1/validation/run" },
            { "method": "GET", "path": "/control/v1/events" },
            { "method": "GET", "path": "/control/v1/auth/session" },
            { "method": "POST", "path": "/control/v1/auth/rotate" },
            { "method": "POST", "path": "/control/v1/auth/revoke" }
        ]
    })
}

fn runtime(port: u16) -> Value {
    json!({
        "service": "alethe-runtime",
        "ready": true,
        "pid": std::process::id(),
        "port": port,
        "cwd": std::env::current_dir().ok().map(|p| p.to_string_lossy().into_owned()),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH
    })
}

fn probe_agent(id: &str, command: &str, execution_supported: bool) -> Value {
    let path = crate::cli_resolver::find_windows_cli_launcher(command);
    let Some(path) = path else {
        return json!({ "id": id, "command": command, "available": false, "execution_supported": false, "status": "unavailable" });
    };
    let version = Command::new(&path)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .chain(String::from_utf8_lossy(&output.stderr).lines())
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().chars().take(256).collect::<String>())
        });
    json!({
        "id": id,
        "command": command,
        "path": path,
        "available": true,
        "execution_supported": execution_supported,
        "status": if execution_supported { "available" } else { "discovered" },
        "version": version
    })
}

/// O que o control plane sabe de cada runtime, do registry e não de uma lista escrita à mão:
/// descoberta do launcher (instalado), prova de efeito (executável pelo control plane) e o perfil
/// irrestrito que o app usa, para o chamador pedir os mesmos args em vez de adivinhar.
fn agents(app: &AppHandle) -> Value {
    let proofs = crate::runtime_registry::load_proofs(app);
    let entries = crate::runtime_registry::RUNTIMES
        .iter()
        .map(|runtime| {
            let proof = proofs.get(runtime.id);
            let mut probe = probe_agent(
                runtime.id,
                runtime.command,
                crate::runtime_registry::proof_ok(&proofs, runtime.id),
            );
            if let Some(proof) = proof {
                probe["proof"] = json!({
                    "ok": proof.ok,
                    "spawn_ok": proof.spawn_ok,
                    "steer_ok": proof.steer_ok,
                    "agent_id": proof.agent_id,
                    "args": proof.args,
                    "boot_inputs": proof.boot_inputs,
                    "proved_at_ms": proof.proved_at_ms,
                });
            }
            probe["unrestricted_args"] = json!(runtime.unrestricted_args);
            probe
        })
        .collect::<Vec<_>>();
    json!({ "agents": entries, "source": "runtime registry (descoberta + prova de efeito)" })
}

fn projects_payload(app: &AppHandle) -> Result<Value, String> {
    let content = crate::projects::load_projects(app.clone())?
        .ok_or_else(|| "projects_not_initialized".to_string())?;
    let data = serde_json::from_str::<Value>(&content)
        .map_err(|error| format!("projects_json_invalid:{error}"))?;
    Ok(json!({ "data": data, "source": "Alethe projects.json" }))
}

fn project_from_payload(payload: &Value, id: &str) -> Option<Value> {
    payload
        .get("projects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(payload.as_array().into_iter().flatten())
        .find(|project| {
            ["id", "project_id", "name", "path", "cwd"]
                .iter()
                .filter_map(|field| project.get(*field).and_then(Value::as_str))
                .any(|value| value == id)
        })
        .cloned()
}

fn terminal_snapshots(app: &AppHandle) -> Result<Vec<Value>, String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    tauri::async_runtime::block_on(crate::pty::list_pty_processes(sessions))?
        .into_iter()
        .map(|snapshot| serde_json::to_value(snapshot).map_err(|error| error.to_string()))
        .collect()
}

fn terminal_by_id(app: &AppHandle, id: &str) -> Result<Option<Value>, String> {
    Ok(terminal_snapshots(app)?.into_iter().find(|snapshot| {
        snapshot.get("id").and_then(Value::as_str) == Some(id)
    }))
}

fn terminal_start(app: &AppHandle, input: TerminalStartInput) -> Result<Value, String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    let remote = app.state::<std::sync::Arc<crate::remote::RemoteHub>>();
    let response = tauri::async_runtime::block_on(crate::pty::spawn_pty(
        app.clone(),
        sessions,
        remote,
        input.cols.unwrap_or(120),
        input.rows.unwrap_or(32),
        input.id,
        input.command,
        input.cwd,
        input.extra_args,
        input.launcher_override,
        input.env,
    ))?;
    serde_json::to_value(response).map_err(|error| error.to_string())
}

fn terminal_write(app: &AppHandle, id: String, data: String) -> Result<(), String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    tauri::async_runtime::block_on(crate::pty::write_pty(sessions, id, data))
}

fn terminal_scrollback(app: &AppHandle, id: String, max_bytes: Option<usize>) -> Result<String, String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    tauri::async_runtime::block_on(crate::pty::attach_pty(app.clone(), sessions, id, max_bytes))
}

fn terminal_kill(app: &AppHandle, id: String) -> Result<(), String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    tauri::async_runtime::block_on(crate::pty::kill_pty(app.clone(), sessions, id))
}

fn terminal_restart(app: &AppHandle, id: String, input: TerminalStartInput) -> Result<Value, String> {
    let sessions = app.state::<crate::pty::PtySessions>();
    let remote = app.state::<std::sync::Arc<crate::remote::RemoteHub>>();
    let response = tauri::async_runtime::block_on(crate::pty::restart_pty(
        app.clone(), sessions, remote, id, input.command, input.cwd, input.extra_args,
        input.launcher_override, input.env,
    ))?;
    serde_json::to_value(response).map_err(|error| error.to_string())
}

fn valid_runtime_id(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.contains(['/', '\\', '?', '#']) {
        return Err("agent_id_invalid".to_string());
    }
    Ok(value.to_string())
}

/// Evento de UI: a sessão que o control plane subiu tem de aparecer na janela **ligada a este pty
/// id**. Antes disto o spawn externo rodava invisível — o renderer monta os panes do próprio store
/// e nunca ficava sabendo da sessão; quem dirigia o control plane por codex e outros harnesses via
/// o processo vivo no `/terminals` e nenhum pane na tela.
pub const PANE_OPEN_EVENT: &str = "control://pane-open";

/// Payload do anúncio: só o que o renderer precisa para achar o projeto e se ligar à sessão que já
/// existe. O id vai junto porque subir um segundo processo só para desenhar o pane seria o defeito
/// — o pane tem de mostrar a sessão real. Nada de tarefa, texto de pedido ou credencial: este é um
/// canal de UI, não de conteúdo.
fn pane_open_payload(pty_id: &str, runtime: &str, cwd: Option<&str>) -> Value {
    json!({
        "pty_id": pty_id,
        "runtime": runtime,
        "cwd": cwd.unwrap_or_default(),
    })
}

fn announce_pane_open(app: &AppHandle, pty_id: &str, runtime: &str, cwd: Option<&str>) {
    let _ = app.emit(PANE_OPEN_EVENT, pane_open_payload(pty_id, runtime, cwd));
}

fn agent_spawn(app: &AppHandle, input: AgentSpawnInput) -> Result<Value, String> {
    let agent = input.agent.trim().to_lowercase();
    let id = valid_runtime_id(&input.id.unwrap_or_else(|| format!("agent-{}", nanoid::nanoid!(12))))?;
    // O gate é o registry, não uma lista escrita à mão: runtime conhecido + CLI instalado + efeito
    // comprovado (prova no disco). Recusar aqui é o contrato da Task 5 — `execution_supported` só é
    // verdadeiro com prova, e a recusa diz qual etapa falta.
    if let Some(reason) = crate::runtime_registry::spawn_denied_reason_from(
        &crate::runtime_registry::load_proofs(app),
        crate::runtime_registry::spec(&agent)
            .and_then(|runtime| crate::cli_resolver::find_windows_cli_launcher(runtime.command))
            .is_some(),
        &agent,
    ) {
        return Err(reason);
    }
    let cwd = input.cwd.clone();
    let terminal = terminal_start(app, TerminalStartInput {
        cols: input.cols,
        rows: input.rows,
        id: Some(id.clone()),
        command: Some(agent.clone()),
        cwd: cwd.clone(),
        extra_args: input.extra_args,
        launcher_override: input.launcher_override,
        env: input.env,
    })?;
    announce_pane_open(app, &id, &agent, cwd.as_deref());
    if let Some(task) = input.task.filter(|value| !value.trim().is_empty()) {
        terminal_write(app, id.clone(), format!("{task}\r\n"))?;
    }
    let payload = json!({ "agent_id": id, "agent": agent, "terminal": terminal, "status": "started", "source": "real Alethe PTY" });
    emit_control_event("agent.started", Some(id.clone()), payload.clone());
    Ok(payload)
}

/// Rotas reconhecidas e deliberadamente NÃO implementadas. `capabilities()` é a promessa feita ao
/// consumidor, então não pode anunciar nada daqui: era o defeito do `resume`, anunciado em
/// `/capabilities` e respondendo 409 fixo, como se a rota existisse. O teste
/// `capabilities_never_announce_an_unimplemented_route` guarda isso.
const NOT_IMPLEMENTED_ROUTES: &[(&str, &str)] = &[("POST", "/control/v1/agents/{id}/resume")];

/// `resume` de agente: o control plane não persiste sessão de agente — agentes vivem como PTY em
/// memória (`PtySessions`) e `restart_pty` exige que o chamador repasse command/cwd/extra_args —
/// então não há sessão guardada para retomar. Responde 501 explícito, não anuncia a rota, e não
/// carrega estado nenhum.
fn agent_resume_route() -> Response<std::io::Cursor<Vec<u8>>> {
    error_response(501, "agent_resume_not_implemented")
}

/// Prova de efeito de um runtime: `POST /control/v1/runtimes/{id}/proof` (corpo opcional `{dir}`).
///
/// Quem dirige a prova é o APP, não o chamador. O gate do spawn recusa runtime sem prova, e provar
/// exige executar o runtime — este é o único caminho que executa um runtime ainda não provado, e ele
/// executa um contrato fixo: o app cria a pasta (se o chamador não indicar uma), sobe o runtime com o
/// perfil irrestrito do próprio registry (o mesmo `UNRESTRICTED_FLAG` que o humano liga no terminal),
/// manda criar `proof-<id>.txt` com `<ID>_OK`, espera o arquivo no disco, manda ALTERAR para
/// `<ID>_STEER_OK` (steer de verdade, na mesma sessão) e espera de novo. Nada de tarefa arbitrária em
/// runtime não provado: o que o chamador escolhe é a pasta, e o app escolhe o resto.
///
/// O efeito é medido lendo o arquivo no disco, etapa por etapa, e o registro só fica `ok` com as duas
/// etapas — a palavra de quem chamou não entra na conta. O pedido é longo de propósito (o runtime
/// pensa): a rota responde quando a prova termina, e o listener atende em thread própria (Task 2),
/// então um pedido longo não segura os outros.
fn runtime_proof_route(app: &AppHandle, id: &str, input: RuntimeProofInput) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(runtime) = crate::runtime_registry::spec(id) else {
        return error_response(422, &format!("agent_runtime_not_supported:{id}"));
    };
    if crate::cli_resolver::find_windows_cli_launcher(runtime.command).is_none() {
        return error_response(422, &format!("runtime_unavailable:{}", runtime.command));
    }
    let dir = match input.dir.map(|dir| dir.trim().to_string()).filter(|dir| !dir.is_empty()) {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::env::temp_dir().join(format!("alethe-proof-{id}-{}", nanoid::nanoid!(8))),
    };
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return error_response(500, &format!("proof_dir_create_failed:{error}"));
    }
    let dir = dir.to_string_lossy().into_owned();
    let agent_id = format!("proof-{id}-{}", nanoid::nanoid!(6));
    let args = runtime
        .unrestricted_args
        .iter()
        .map(|arg| arg.to_string())
        .collect::<Vec<_>>();

    match run_runtime_proof(app, id, &agent_id, &dir, &args) {
        Ok(record) => {
            let payload = json!({
                "runtime": id,
                "command": runtime.command,
                "dir": dir,
                "execution_supported": record.ok,
                "proof": record,
            });
            if record.ok {
                json_response(200, payload)
            } else {
                json_response(422, payload)
            }
        }
        Err(error) => error_response(500, &error),
    }
}

/// Executa o contrato da prova e devolve o registro do que foi medido. Cada etapa exige o arquivo no
/// disco com o conteúdo exato: `spawn` = o runtime criou; `steer` = o runtime obedeceu uma segunda
/// instrução na mesma sessão. Falha em qualquer ponto encerra a sessão e devolve o registro parcial
/// (com o motivo), porque meia prova é informação, não sucesso.
fn run_runtime_proof(
    app: &AppHandle,
    id: &str,
    agent_id: &str,
    dir: &str,
    args: &[String],
) -> Result<crate::runtime_registry::ProofRecord, String> {
    let started = terminal_start(
        app,
        TerminalStartInput {
            cols: Some(120),
            rows: Some(30),
            id: Some(agent_id.to_string()),
            command: Some(id.to_string()),
            cwd: Some(dir.to_string()),
            extra_args: Some(args.to_vec()),
            launcher_override: None,
            env: None,
        },
    );
    if let Err(error) = started {
        return Ok(crate::runtime_registry::ProofRecord {
            detail: format!("spawn falhou: {error}"),
            ..crate::runtime_registry::ProofRecord::new(id, agent_id, args.to_vec(), dir)
        });
    }

    let file = std::path::Path::new(dir).join(crate::runtime_registry::proof_file_name(id));
    let mut record = crate::runtime_registry::ProofRecord::new(id, agent_id, args.to_vec(), dir);
    record.file = file.to_string_lossy().into_owned();

    // O CLI precisa terminar de subir antes de receber texto: o prompt digitado cedo demais se perde
    // na tela de boot. Espera a saída parar de crescer (a TUI desenhou e está esperando) com teto.
    wait_for_output_to_settle(app, agent_id, Duration::from_secs(25), Duration::from_millis(1500));

    // Antes do pedido, o handshake do runtime: CLIs de agente abrem diálogos de primeira execução
    // por conta própria (o claude pergunta se confia na pasta e fica esperando resposta — medido no
    // scrollback da sessão de prova). O texto do pedido digitado dentro desse diálogo não vira ação.
    // O handshake do registry fecha o diálogo aceitando a opção padrão, como faria um humano.
    for input in crate::runtime_registry::boot_inputs(id) {
        if let Err(error) = terminal_write(app, agent_id.to_string(), format!("{input}\r")) {
            record.detail = format!("handshake de boot falhou: {error}");
            return close_proof(app, agent_id, record);
        }
        record.boot_inputs.push((*input).to_string());
        wait_for_output_to_settle(app, agent_id, Duration::from_secs(20), Duration::from_millis(1200));
    }

    let spawn_prompt = crate::runtime_registry::proof_prompt(id, dir, crate::runtime_registry::ProofStage::Spawn);
    if let Err(error) = send_prompt(app, agent_id, &spawn_prompt) {
        record.detail = format!("send do spawn falhou: {error}");
        return close_proof(app, agent_id, record);
    }
    let spawn_seen = wait_for_proof_file(
        &file,
        &crate::runtime_registry::proof_expected(id, crate::runtime_registry::ProofStage::Spawn),
        Duration::from_secs(240),
    );
    record.spawn_ok = spawn_seen;
    if !spawn_seen {
        record.detail = "etapa spawn sem efeito: arquivo não apareceu com o conteúdo esperado".to_string();
        return close_proof(app, agent_id, record);
    }
    record.content = crate::runtime_registry::proof_expected(id, crate::runtime_registry::ProofStage::Spawn);

    let steer_prompt = crate::runtime_registry::proof_prompt(id, dir, crate::runtime_registry::ProofStage::Steer);
    if let Err(error) = send_prompt(app, agent_id, &steer_prompt) {
        record.detail = format!("steer falhou: {error}");
        return close_proof(app, agent_id, record);
    }
    let steer_seen = wait_for_proof_file(
        &file,
        &crate::runtime_registry::proof_expected(id, crate::runtime_registry::ProofStage::Steer),
        Duration::from_secs(240),
    );
    record.steer_ok = steer_seen;
    record.ok = record.spawn_ok && record.steer_ok;
    record.detail = if steer_seen {
        "spawn e steer medidos no disco".to_string()
    } else {
        "etapa steer sem efeito: o arquivo não mudou para o conteúdo esperado".to_string()
    };
    if steer_seen {
        record.content = crate::runtime_registry::proof_expected(id, crate::runtime_registry::ProofStage::Steer);
    }

    close_proof(app, agent_id, record)
}

/// Fecha a prova: guarda o rastro da sessão, encerra a sessão e grava o registro — inclusive quando
/// a etapa falhou. Registro de falha não é ruído: é o que faz o gate responder *por que* aquele
/// runtime está sem prova (e o que sobrevive ao scrollback, que morre com a sessão).
fn close_proof(
    app: &AppHandle,
    agent_id: &str,
    mut record: crate::runtime_registry::ProofRecord,
) -> Result<crate::runtime_registry::ProofRecord, String> {
    record.output_tail = proof_output_tail(app, agent_id);
    let _ = terminal_kill(app, agent_id.to_string());
    let _ = crate::runtime_registry::record_proof(app, &record)?;
    Ok(record)
}

/// Manda um pedido como um humano manda: o texto numa escrita e o Enter noutra, com uma pausa entre
/// as duas. Medido: com o texto e o `\r` na mesma escrita, a TUI trata o Enter como parte de um paste
/// e o pedido fica parado no campo de entrada — foi assim que claude, codex, opencode e antigravity
/// ficaram 240s "sem efeito" com o CLI pronto na tela; com o Enter separado, o antigravity escreveu o
/// arquivo da prova em 25s. No shell (pwsh) o Enter executa o comando do mesmo jeito, então o mesmo
/// caminho serve para os dois drivers.
fn send_prompt(app: &AppHandle, agent_id: &str, prompt: &str) -> Result<(), String> {
    terminal_write(app, agent_id.to_string(), prompt.to_string())?;
    std::thread::sleep(Duration::from_millis(600));
    terminal_write(app, agent_id.to_string(), "\r".to_string())
}

/// Tira as sequências de terminal (CSI de cor/posição, OSC de título) e devolve texto em linhas
/// curtas, sem repetição seguida. É o que sobra da tela de uma sessão, legível por humano e por log.
fn strip_terminal_escapes(raw: &str) -> Vec<String> {
    let mut clean = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\u{1b}' {
            clean.push(character);
            continue;
        }
        match chars.next() {
            // CSI: `ESC [ … final` (o final está em @..~)
            Some('[') => {
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            // OSC: `ESC ] … BEL` ou `ESC ] … ESC \`
            Some(']') => {
                while let Some(next) = chars.next() {
                    if next == '\u{7}' {
                        break;
                    }
                    if next == '\u{1b}' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    let mut lines: Vec<String> = Vec::new();
    for line in clean.split(['\r', '\n']) {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() || lines.last() == Some(&line) {
            continue;
        }
        lines.push(line);
    }
    lines
}

/// Rastro do que a sessão de prova mostrou, para o registro explicar a reprovação sozinho: o
/// scrollback da sessão morre junto com ela, e sem isto o motivo se perde (foi assim que a prova do
/// claude ficou 244s "sem efeito" sem dizer que a TUI estava esperando resposta de um diálogo).
fn proof_output_tail(app: &AppHandle, agent_id: &str) -> String {
    let raw = terminal_scrollback(app, agent_id.to_string(), Some(16384)).unwrap_or_default();
    let lines = strip_terminal_escapes(&raw);
    let tail = lines
        .iter()
        .rev()
        .take(12)
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    tail.chars().take(2000).collect()
}

/// Espera a saída do terminal parar de crescer: o CLI subiu e está esperando input. Não é leitura de
/// tela (nada de casar texto de TUI, que muda de versão para versão): é ausência de movimento.
fn wait_for_output_to_settle(app: &AppHandle, agent_id: &str, limit: Duration, quiet: Duration) {
    let started = Instant::now();
    let mut last_len = 0usize;
    let mut last_change = Instant::now();
    while started.elapsed() < limit {
        let len = terminal_scrollback(app, agent_id.to_string(), Some(4096))
            .map(|output| output.len())
            .unwrap_or(0);
        if len != last_len {
            last_len = len;
            last_change = Instant::now();
        } else if last_change.elapsed() >= quiet {
            return;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

/// Espera o arquivo da prova existir com o conteúdo exato (trim). Devolve `false` no teto — quem
/// chama registra a etapa como não medida, nunca como sucesso.
fn wait_for_proof_file(file: &std::path::Path, expected: &str, limit: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < limit {
        if std::fs::read_to_string(file)
            .map(|content| content.trim() == expected)
            .unwrap_or(false)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn runtime_route(
    app: &AppHandle,
    method: &str,
    path: &str,
    request: &mut Request,
) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    let rest = path.strip_prefix("/control/v1/runtimes/")?;
    let (id, action) = rest.split_once('/')?;
    let id = id.trim();
    if action != "proof" {
        return Some(error_response(404, "control_route_not_found"));
    }
    if method != "POST" {
        return Some(error_response(405, "method_not_allowed"));
    }
    let input = match read_json::<RuntimeProofInput>(request) {
        Ok(input) => input,
        Err(error) => return Some(error_response(400, &error)),
    };
    Some(runtime_proof_route(app, id, input))
}

fn agent_route(app: &AppHandle, method: &str, path: &str, url: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {    if method == "POST" && path == "/control/v1/agents/spawn" {
        return Some(match read_json::<AgentSpawnInput>(request).and_then(|input| agent_spawn(app, input)) {
            Ok(payload) => json_response(201, payload),
            Err(error) if error.starts_with("agent_runtime_not_supported") => error_response(422, &error),
            Err(error) => error_response(400, &error),
        });
    }
    let suffix = path.strip_prefix("/control/v1/agents/")?;
    let mut segments = suffix.split('/');
    let id = valid_runtime_id(segments.next().unwrap_or_default()).ok()?;
    let action = segments.next();
    if segments.next().is_some() {
        return Some(error_response(404, "control_route_not_found"));
    }
    match (method, action) {
        ("GET", None) | ("GET", Some("status")) => Some(match terminal_by_id(app, &id) {
            Ok(Some(status)) => json_response(200, json!({ "agent_id": id, "status": status, "source": "active Alethe PTY" })),
            Ok(None) => error_response(404, "agent_not_found"),
            Err(error) => error_response(500, &error),
        }),
        ("GET", Some("output")) => Some(match terminal_scrollback(app, id.clone(), query_parameter(url, "max_bytes").and_then(|v| v.parse().ok())) {
            Ok(output) => json_response(200, json!({ "agent_id": id, "output": output })),
            Err(error) => error_response(404, &error),
        }),
        ("POST", Some("send")) | ("POST", Some("steer")) => Some(match read_json::<AgentMessageInput>(request).and_then(|input| {
            let message = input.message.or(input.data).filter(|value| !value.is_empty()).ok_or_else(|| "agent_message_required".to_string())?;
            // O consumidor precisa saber que o agente voltou a trabalhar, não o que foi escrito nele:
            // a mensagem é do usuário e o evento é persistido. Sai o tamanho, não o texto.
            let bytes = message.len();
            let source = if action == Some("steer") { "steer" } else { "send" };
            terminal_write(app, id.clone(), message)?;
            emit_control_event(
                "agent.working",
                Some(id.clone()),
                json!({ "agent_id": id, "source": source, "message_bytes": bytes }),
            );
            Ok::<Value, String>(json!({ "agent_id": id, "accepted": true }))
        }) {
            Ok(payload) => json_response(200, payload),
            Err(error) => error_response(400, &error),
        }),
        ("POST", Some("interrupt")) => Some(match terminal_write(app, id, "\u{3}".to_string()) {
            Ok(()) => json_response(200, json!({ "accepted": true, "signal": "SIGINT" })),
            Err(error) => error_response(404, &error),
        }),
        ("POST", Some("stop")) => Some(match terminal_kill(app, id) {
            Ok(()) => json_response(200, json!({ "stopped": true })),
            Err(error) => error_response(404, &error),
        }),
        ("POST", Some("resume")) => Some(agent_resume_route()),
        _ => Some(error_response(404, "control_route_not_found")),
    }
}

fn filesystem_route(method: &str, path: &str, url: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    match (method, path) {
        ("GET", "/control/v1/fs/list") => Some(match query_parameter(url, "path").ok_or_else(|| "path_required".to_string()).and_then(crate::filesystem::list_directory) {
            Ok(entries) => json_response(200, json!({ "entries": entries })),
            Err(error) => error_response(400, &error),
        }),
        ("GET", "/control/v1/fs/read") => Some(match query_parameter(url, "path").ok_or_else(|| "path_required".to_string()).and_then(crate::filesystem::read_text_file) {
            Ok(content) => json_response(200, json!({ "content": content })),
            Err(error) => error_response(400, &error),
        }),
        ("PUT", "/control/v1/fs/write") => Some({
            let outcome = read_json::<FilesystemWriteInput>(request).and_then(|input| {
                let path = std::path::PathBuf::from(input.path.trim());
                if path.as_os_str().is_empty() {
                    return Err("path_required".to_string());
                }
                if !path.parent().is_some_and(|parent| parent.is_dir()) {
                    return Err("parent_directory_not_found".to_string());
                }
                std::fs::write(&path, input.content)
                    .map_err(|error| error.to_string())
                    .map(|()| path.to_string_lossy().to_string())
            });
            match outcome {
                Ok(path) => {
                    emit_file_changed("write", path, None);
                    json_response(200, json!({ "written": true }))
                }
                Err(error) => error_response(400, &error),
            }
        }),
        ("POST", "/control/v1/fs/mkdir") => Some({
            let outcome = read_json::<FilesystemPathInput>(request).and_then(|input| {
                std::fs::create_dir_all(&input.path)
                    .map_err(|error| error.to_string())
                    .map(|()| input.path)
            });
            match outcome {
                Ok(path) => {
                    emit_file_changed("mkdir", path, None);
                    json_response(201, json!({ "created": true }))
                }
                Err(error) => error_response(400, &error),
            }
        }),
        ("POST", "/control/v1/fs/move") => Some({
            let outcome = read_json::<FilesystemMoveInput>(request).and_then(|input| {
                std::fs::rename(&input.path, &input.destination)
                    .map_err(|error| error.to_string())
                    .map(|()| (input.path, input.destination))
            });
            match outcome {
                Ok((path, destination)) => {
                    emit_file_changed("move", path, Some(destination));
                    json_response(200, json!({ "moved": true }))
                }
                Err(error) => error_response(400, &error),
            }
        }),
        ("DELETE", "/control/v1/fs") => Some({
            let outcome = read_json::<FilesystemPathInput>(request)
                .or_else(|_| {
                    query_parameter(url, "path")
                        .map(|path| FilesystemPathInput { path })
                        .ok_or_else(|| "path_required".to_string())
                })
                .and_then(|input| {
                    crate::filesystem::delete_filesystem_entry(input.path.clone())
                        .map_err(|error| error.to_string())
                        .map(|()| input.path)
                });
            match outcome {
                Ok(path) => {
                    emit_file_changed("delete", path, None);
                    json_response(200, json!({ "deleted": true }))
                }
                Err(error) => error_response(400, &error),
            }
        }),
        _ => None,
    }
}

fn git_route(method: &str, path: &str, url: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if method == "GET" {
        let repo = query_parameter(url, "repo")?;
        return match path {
            "/control/v1/git/status" => Some(match tauri::async_runtime::block_on(crate::git_control::git_status(repo)) {
                Ok(status) => json_response(200, json!({ "status": status })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/diff" => Some(match crate::git_control::git_diff(repo, query_parameter(url, "path").unwrap_or_default(), query_parameter(url, "staged").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))) {
                Ok(diff) => json_response(200, json!({ "diff": diff })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/log" => Some(match tauri::async_runtime::block_on(crate::git_control::git_log_graph(repo, query_parameter(url, "max_count").and_then(|v| v.parse().ok()).unwrap_or(50).min(500))) {
                Ok(commits) => json_response(200, json!({ "commits": commits })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/branches" => Some(match tauri::async_runtime::block_on(crate::git_control::git_list_branches(repo)) {
                Ok(branches) => json_response(200, json!({ "branches": branches })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/incoming-outgoing" => Some(match tauri::async_runtime::block_on(crate::git_control::git_incoming_outgoing(repo)) {
                Ok(value) => json_response(200, json!({ "incoming_outgoing": value })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/worktrees" => Some(match tauri::async_runtime::block_on(crate::worktrees::worktree_list(repo)) {
                Ok(worktrees) => json_response(200, json!({ "worktrees": worktrees })),
                Err(error) => error_response(400, &error),
            }),
            path if path.starts_with("/control/v1/worktrees/") && path.ends_with("/changes") => {
                let id = path.trim_start_matches("/control/v1/worktrees/").trim_end_matches("/changes").trim_end_matches('/');
                Some(match tauri::async_runtime::block_on(crate::worktrees::worktree_pending_changes(repo, id.to_string())) {
                    Ok(changes) => json_response(200, json!({ "changes": changes })),
                    Err(error) => error_response(400, &error),
                })
            }
            _ => None,
        };
    }
    if method == "POST" {
        return match path {
            "/control/v1/git/init" => Some({
                let outcome = read_json::<GitInitInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_init(input.path))
                });
                match outcome {
                    Ok(repo_root) => {
                        // `git_init` devolve o caminho canonicalizado (`\\?\C:\...` no Windows); o
                        // evento leva a forma sem o prefixo verbatim, que é a que o consumidor
                        // consegue casar com os caminhos que ele mesmo usa. A resposta da rota
                        // continua devolvendo o caminho do jeito que sempre devolveu.
                        let repo = crate::worktrees::git_arg(std::path::Path::new(&repo_root));
                        emit_git_changed("init", repo, &[]);
                        json_response(201, json!({ "repo_root": repo_root }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/stage" => Some({
                let outcome = read_json::<GitPathsInput>(request).and_then(|input| {
                    let path_count = input.paths.len();
                    tauri::async_runtime::block_on(crate::git_control::git_stage(input.repo_root.clone(), input.paths))
                        .map(|()| (input.repo_root, path_count))
                });
                match outcome {
                    Ok((repo, path_count)) => {
                        emit_git_changed("stage", repo, &[("path_count", json!(path_count))]);
                        json_response(200, json!({ "staged": true }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/unstage" => Some({
                let outcome = read_json::<GitPathsInput>(request).and_then(|input| {
                    let path_count = input.paths.len();
                    tauri::async_runtime::block_on(crate::git_control::git_unstage(input.repo_root.clone(), input.paths))
                        .map(|()| (input.repo_root, path_count))
                });
                match outcome {
                    Ok((repo, path_count)) => {
                        emit_git_changed("unstage", repo, &[("path_count", json!(path_count))]);
                        json_response(200, json!({ "unstaged": true }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/discard" => Some({
                let outcome = read_json::<GitDiscardInput>(request).and_then(|input| {
                    let path_count = input.paths.len();
                    tauri::async_runtime::block_on(crate::git_control::git_discard(input.repo_root.clone(), input.paths, input.untracked))
                        .map(|()| (input.repo_root, path_count))
                });
                match outcome {
                    Ok((repo, path_count)) => {
                        emit_git_changed("discard", repo, &[("path_count", json!(path_count))]);
                        json_response(200, json!({ "discarded": true }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/commit" => Some({
                let outcome = read_json::<GitCommitInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_commit(input.repo_root.clone(), input.message))
                        .map(|output| (input.repo_root, output))
                });
                match outcome {
                    Ok((repo, output)) => {
                        emit_git_changed("commit", repo, &[]);
                        json_response(200, json!({ "committed": true, "output": output }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/pull" => Some({
                let outcome = read_json::<GitInitInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_pull(input.path.clone()))
                        .map(|output| (input.path, output))
                });
                match outcome {
                    Ok((repo, output)) => {
                        emit_git_changed("pull", repo, &[]);
                        json_response(200, json!({ "pulled": true, "output": output }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/push" => Some({
                let outcome = read_json::<GitInitInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_push(input.path.clone()))
                        .map(|output| (input.path, output))
                });
                match outcome {
                    Ok((repo, output)) => {
                        emit_git_changed("push", repo, &[]);
                        json_response(200, json!({ "pushed": true, "output": output }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/branch" => Some({
                let outcome = read_json::<GitBranchInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_create_branch_from_commit(input.repo.clone(), input.hash, input.branch_name))
                        .map(|()| input.repo)
                });
                match outcome {
                    Ok(repo) => {
                        emit_git_changed("branch", repo, &[]);
                        json_response(201, json!({ "created": true }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/cherry-pick" => Some({
                let outcome = read_json::<GitHashInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_cherry_pick_commit(input.repo.clone(), input.hash))
                        .map(|output| (input.repo, output))
                });
                match outcome {
                    Ok((repo, output)) => {
                        emit_git_changed("cherry-pick", repo, &[]);
                        json_response(200, json!({ "cherry_picked": true, "output": output }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/revert" => Some({
                let outcome = read_json::<GitHashInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::git_control::git_revert_commit(input.repo.clone(), input.hash))
                        .map(|output| (input.repo, output))
                });
                match outcome {
                    Ok((repo, output)) => {
                        emit_git_changed("revert", repo, &[]);
                        json_response(200, json!({ "reverted": true, "output": output }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/git/reset" => Some({
                let outcome = read_json::<GitResetInput>(request).and_then(|input| {
                    let mode = input.mode.clone();
                    tauri::async_runtime::block_on(crate::git_control::git_reset_to_commit(input.repo.clone(), input.hash, input.mode))
                        .map(|()| (input.repo, mode))
                });
                match outcome {
                    Ok((repo, mode)) => {
                        emit_git_changed("reset", repo, &[("mode", json!(mode))]);
                        json_response(200, json!({ "reset": true }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            "/control/v1/worktrees" => Some({
                let outcome = read_json::<WorktreeProvisionInput>(request).and_then(|input| {
                    tauri::async_runtime::block_on(crate::worktrees::worktree_provision(input.repo.clone(), input.agent_id, input.mode))
                        .map(|worktree| (input.repo, worktree))
                });
                match outcome {
                    Ok((repo, worktree)) => {
                        // `agent_id` vai no envelope (convenção do bus: o webview filtra por ele) e no
                        // payload (o consumidor do SSE lê o `data`). `repo` é o repositório principal; o
                        // caminho da cópia de trabalho fica na resposta, não no evento.
                        emit_control_event(
                            "worktree.created",
                            Some(worktree.agent_id.clone()),
                            json!({ "agent_id": worktree.agent_id, "mode": worktree.mode, "repo": repo }),
                        );
                        json_response(201, json!({ "worktree": worktree }))
                    }
                    Err(error) => error_response(400, &error),
                }
            }),
            path if path.starts_with("/control/v1/worktrees/") && path.ends_with("/lock") => {
                Some(match read_json::<WorktreeLockInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::worktrees::worktree_lock(input.repo, input.agent_id, input.reason))) {
                    Ok(()) => json_response(200, json!({ "locked": true })),
                    Err(error) => error_response(400, &error),
                })
            }
            path if path.starts_with("/control/v1/worktrees/") && path.ends_with("/unlock") => {
                Some(match read_json::<WorktreeAgentInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::worktrees::worktree_unlock(input.repo, input.agent_id))) {
                    Ok(()) => json_response(200, json!({ "unlocked": true })),
                    Err(error) => error_response(400, &error),
                })
            }
            path if path.starts_with("/control/v1/worktrees/") && path.ends_with("/fetch") => {
                Some(match read_json::<WorktreeAgentInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::worktrees::worktree_fetch_branch(input.repo, input.agent_id))) {
                    Ok(()) => json_response(200, json!({ "fetched": true })),
                    Err(error) => error_response(400, &error),
                })
            }
            path if path.starts_with("/control/v1/worktrees/") && path.ends_with("/commit") => {
                Some(match read_json::<WorktreeCommitInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::worktrees::worktree_commit_worktree(input.repo, input.agent_id, input.message))) {
                    Ok(committed) => json_response(200, json!({ "committed": committed })),
                    Err(error) => error_response(400, &error),
                })
            }
            _ => None,
        };
    }
    if method == "DELETE" && path.starts_with("/control/v1/worktrees/") {
        let agent_id = path.trim_start_matches("/control/v1/worktrees/");
        let Some(repo) = query_parameter(url, "repo") else { return Some(error_response(400, "repo_required")); };
        let force = query_parameter(url, "force").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        return Some(match tauri::async_runtime::block_on(crate::worktrees::worktree_remove(repo.clone(), agent_id.to_string(), force)) {
            Ok(()) => {
                // `force` diz se o descarte levou trabalho não commitado junto — é o que o consumidor
                // precisa para saber que aquilo ali não foi só uma pasta removida.
                emit_control_event(
                    "worktree.removed",
                    Some(agent_id.to_string()),
                    json!({ "agent_id": agent_id, "repo": repo, "force": force }),
                );
                json_response(200, json!({ "deleted": true }))
            }
            Err(error) => error_response(400, &error),
        });
    }
    None
}

fn validation_route(method: &str, path: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if method != "POST" || path != "/control/v1/validation/run" {
        return None;
    }
    let input = match read_json::<ValidationInput>(request) {
        Ok(input) => input,
        Err(error) => return Some(error_response(400, &error)),
    };
    let command_count = input
        .commands
        .iter()
        .filter(|command| !command.trim().is_empty())
        .count();
    // `run_id` é o que deixa o consumidor casar started/completed quando duas validações correm ao
    // mesmo tempo (cada requisição tem a própria thread). O correlation_id do envelope é por evento,
    // não por rodada, então não serve para isso.
    let run_id = nanoid::nanoid!(12);
    let cwd = input.cwd;
    emit_control_event(
        "validation.started",
        None,
        json!({ "run_id": run_id, "cwd": cwd, "command_count": command_count }),
    );

    let started = std::time::Instant::now();
    let outcome = crate::validation::run_validation(cwd.clone(), input.commands);
    let duration_ms = started.elapsed().as_millis() as u64;

    // O payload leva o veredito, nunca o conteúdo: `stage` é a linha de comando e `output` é o
    // stdout/stderr da rodada, os dois ficam fora (é a superfície que o Jev marcou como risco alto).
    // `error` é token fixo do próprio módulo (`directory_not_found`), não texto livre.
    let completion = match &outcome {
        Ok(validation) => json!({
            "run_id": run_id,
            "cwd": cwd,
            "command_count": command_count,
            "duration_ms": duration_ms,
            "success": validation.success,
            "ran_any_command": validation.ran_any_command,
        }),
        // Mesmo no erro o `completed` sai: quem viu o `started` não pode ficar pendurado esperando um
        // evento que nunca vem. `success: false` é o veredito honesto — a validação não passou.
        Err(error) => json!({
            "run_id": run_id,
            "cwd": cwd,
            "command_count": command_count,
            "duration_ms": duration_ms,
            "success": false,
            "error": error,
        }),
    };
    emit_control_event("validation.completed", None, completion);

    Some(match outcome {
        Ok(validation) => json_response(200, json!({ "validation": validation })),
        Err(error) => error_response(400, &error),
    })
}

fn bearer_token(request: &Request) -> Option<&str> {
    request
        .headers()
        .iter()
        .find(|header| {
            header
                .field
                .as_str()
                .to_string()
                .eq_ignore_ascii_case("Authorization")
        })
        .and_then(|header| header.value.as_str().strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn unauthorized_response() -> Response<std::io::Cursor<Vec<u8>>> {
    error_response(401, "authentication_required")
        .with_header(Header::from_bytes("WWW-Authenticate", "Bearer").expect("static header"))
}

pub fn handle_request(app: AppHandle, mut request: Request, url: &str, port: u16) -> bool {
    if !is_control_path(url) {
        return false;
    }
    let method = request.method().to_string();
    let path = endpoint_path(url);
    let mut request = match events_route(&method, path, request) {
        Some(restored) => restored,
        None => return true,
    };

    match (method.as_str(), path) {
        ("GET", "/control/v1/health") => { let _ = request.respond(json_response(200, health(port))); return true; }
        ("GET", "/control/v1/version") => { let _ = request.respond(json_response(200, version())); return true; }
        ("GET", "/control/v1/capabilities") => { let _ = request.respond(json_response(200, capabilities())); return true; }
        _ => {}
    }

    if let Some(response) = pairing_route(&method, path, &mut request) {
        // A minimised window has its timers throttled, so the prompt is pushed instead of polled:
        // the event carries no code, and the window reads that over IPC.
        if path == "/control/v1/pairing/start" && response.status_code().0 == 200 {
            let _ = app.emit(PAIRING_REQUESTED_EVENT, json!({ "source": "control-plane" }));
        }
        let _ = request.respond(response);
        return true;
    }

    let Some(token) = bearer_token(&request) else { let _ = request.respond(unauthorized_response()); return true; };
    if state().authenticate(token).is_err() { let _ = request.respond(unauthorized_response()); return true; }

    let response = if path == "/control/v1/runtime" && method == "GET" {
        json_response(200, runtime(port))
    } else if path == "/control/v1/agents" && method == "GET" {
        json_response(200, agents(&app))
    } else if path.starts_with("/control/v1/runtimes/") {
        runtime_route(&app, &method, path, &mut request).unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if path.starts_with("/control/v1/agents/") {
        agent_route(&app, &method, path, url, &mut request).unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if path.starts_with("/control/v1/fs/") || path == "/control/v1/fs" {
        filesystem_route(&method, path, url, &mut request).unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if path.starts_with("/control/v1/git/") || path == "/control/v1/worktrees" || path.starts_with("/control/v1/worktrees/") {
        git_route(&method, path, url, &mut request).unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if path.starts_with("/control/v1/validation/") {
        validation_route(&method, path, &mut request).unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if path == "/control/v1/projects" && method == "GET" {
        match projects_payload(&app) {
            Ok(payload) => json_response(200, payload),
            Err(error) if error == "projects_not_initialized" => json_response(200, json!({ "data": null, "source": "Alethe projects.json" })),
            Err(error) => error_response(500, &error),
        }
    } else if path.starts_with("/control/v1/projects/") && method == "GET" {
        match projects_payload(&app) {
            Ok(payload) => match project_from_payload(&payload["data"], path.trim_start_matches("/control/v1/projects/")) {
                Some(project) => json_response(200, json!({ "project": project })),
                None => error_response(404, "project_not_found"),
            },
            Err(error) => error_response(500, &error),
        }
    } else if path == "/control/v1/targets" && method == "GET" {
        match terminal_snapshots(&app) {
            Ok(targets) => json_response(200, json!({ "targets": targets, "source": "active Alethe PTY sessions" })),
            Err(error) => error_response(500, &error),
        }
    } else if path.starts_with("/control/v1/targets/") && method == "GET" {
        match terminal_by_id(&app, path.trim_start_matches("/control/v1/targets/")) {
            Ok(Some(target)) => json_response(200, json!({ "target": target })),
            Ok(None) => error_response(404, "target_not_found"),
            Err(error) => error_response(500, &error),
        }
    } else if path == "/control/v1/terminals" && method == "POST" {
        match read_json::<TerminalStartInput>(&mut request).and_then(|input| {
            let runtime = input.command.clone().unwrap_or_default();
            let cwd = input.cwd.clone();
            terminal_start(&app, input).map(|payload| (payload, runtime, cwd))
        }) {
            Ok((payload, runtime, cwd)) => {
                // O chamador externo pediu uma sessão: ela aparece na janela ligada a este pty id.
                if let Some(id) = payload.get("id").and_then(|value| value.as_str()) {
                    announce_pane_open(&app, id, &runtime, cwd.as_deref());
                }
                json_response(201, payload)
            }
            Err(error) => error_response(400, &error),
        }
    } else if path == "/control/v1/terminals" && method == "GET" {
        match terminal_snapshots(&app) {
            Ok(terminals) => json_response(200, json!({ "terminals": terminals })),
            Err(error) => error_response(500, &error),
        }
    } else if path.starts_with("/control/v1/terminals/") {
        terminal_route(&app, &method, path, url, &mut request)
            .unwrap_or_else(|| error_response(404, "control_route_not_found"))
    } else if let Some(response) = auth_route(&method, path, token) {
        response
    } else if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
        error_response(405, "method_not_allowed")
    } else {
        error_response(404, "control_route_not_found")
    };
    let _ = request.respond(response);
    true
}

/// As rotas de sessão (`/auth/session`, `/auth/rotate`, `/auth/revoke`). Estão aqui, e não inline no
/// `handle_request`, porque a suíte de auth roda contra um listener real que não monta `AppHandle`:
/// o harness de teste chama esta função, então o que a suíte exercita é o mesmo código que atende o
/// cliente, e não uma cópia. `token` é o Bearer já autenticado pelo chamador — a checagem global de
/// auth continua sendo a única porta, e nenhuma rota daqui afrouxa isso.
fn auth_route(
    method: &str,
    path: &str,
    token: &str,
) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    let response = match (method, path) {
        ("GET", "/control/v1/auth/session") => match state().authenticate(token) {
            Ok(session) => json_response(200, json!({ "authenticated": true, "client_id": session.client_id, "created_at": session.created_at, "expires_at": session.expires_at })),
            Err(_) => unauthorized_response(),
        },
        ("POST", "/control/v1/auth/rotate") => match state().rotate(token) {
            Ok(payload) => json_response(200, payload),
            Err(_) => unauthorized_response(),
        },
        ("POST", "/control/v1/auth/revoke") => match state().revoke(token) {
            Ok(payload) => json_response(200, payload),
            Err(_) => unauthorized_response(),
        },
        _ => return None,
    };
    Some(response)
}

fn terminal_route(app: &AppHandle, method: &str, path: &str, url: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    let suffix = path.strip_prefix("/control/v1/terminals/")?;
    let mut segments = suffix.split('/');
    let id = segments.next()?.to_string();
    let action = segments.next();
    if segments.next().is_some() || id.is_empty() {
        return Some(error_response(404, "terminal_not_found"));
    }
    match (method, action) {
        ("GET", None) => Some(match terminal_by_id(app, &id) {
            Ok(Some(terminal)) => json_response(200, json!({ "terminal": terminal })),
            Ok(None) => error_response(404, "terminal_not_found"),
            Err(error) => error_response(500, &error),
        }),
        ("POST", Some("input")) => Some(match read_json::<TerminalInput>(request).and_then(|input| terminal_write(app, id, input.data)) {
            Ok(()) => json_response(200, json!({ "accepted": true })),
            Err(error) => error_response(400, &error),
        }),
        ("GET", Some("scrollback")) => Some(match terminal_scrollback(app, id.clone(), query_parameter(url, "max_bytes").and_then(|v| v.parse().ok())) {
            Ok(output) => json_response(200, json!({ "terminal_id": id, "output": output })),
            Err(error) => error_response(404, &error),
        }),
        ("POST", Some("interrupt")) => Some(match terminal_write(app, id, "\u{3}".to_string()) {
            Ok(()) => json_response(200, json!({ "accepted": true, "signal": "SIGINT" })),
            Err(error) => error_response(404, &error),
        }),
        ("POST", Some("restart")) => Some(match read_json::<TerminalStartInput>(request).and_then(|input| terminal_restart(app, id, input)) {
            Ok(payload) => json_response(200, payload),
            Err(error) => error_response(400, &error),
        }),
        ("DELETE", None) => Some(match terminal_kill(app, id) {
            Ok(()) => json_response(200, json!({ "deleted": true })),
            Err(error) => error_response(404, &error),
        }),
        _ => Some(error_response(404, "control_route_not_found")),
    }
}

/// Public pairing routes, split out of `handle_request` so the flow can be driven over a real
/// socket without an `AppHandle`.
fn pairing_route(
    method: &str,
    path: &str,
    request: &mut Request,
) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    match (method, path) {
        ("POST", "/control/v1/pairing/start") => Some(
            match read_json::<PairingStartInput>(request)
                .and_then(|input| state().start_pairing(input.client_id))
            {
                Ok(payload) => json_response(200, payload),
                Err(error) => error_response(400, &error),
            },
        ),
        ("POST", "/control/v1/pairing/complete") => Some(
            match read_json::<PairingCompleteInput>(request)
                .and_then(|input| state().complete_pairing(input))
            {
                Ok(payload) => json_response(200, payload),
                Err(error) => error_response(
                    if error.starts_with("credential_") { 503 } else { 400 },
                    &error,
                ),
            },
        ),
        _ => None,
    }
}

/// The Alethe window reads the pending pairing request through here. Tauri IPC is the only channel
/// that reaches this, which is what keeps the code away from the HTTP client asking to pair.
#[tauri::command]
pub fn control_pairing_pending() -> Result<Value, String> {
    state().pairing_pending()
}

/// The human decision behind [Permitir]/[Recusar]: approving here is what lets `complete_pairing`
/// mint a token.
#[tauri::command]
pub fn control_pairing_decide(approve: bool) -> Result<Value, String> {
    state().pairing_decide(approve)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_contract_is_loopback_and_ready() {
        let payload = health(9123);
        assert_eq!(payload["service"], "alethe-control");
        assert_eq!(payload["ready"], true);
        assert_eq!(payload["bind"], "127.0.0.1");
        assert_eq!(payload["port"], 9123);
    }

    #[test]
    fn control_path_requires_v1() {
        assert!(is_control_path("/control/v1/health?x=1"));
        assert!(!is_control_path("/control/v123/health"));
        assert!(!is_control_path("/api/control/v1/health"));
    }

    #[test]
    fn client_ids_are_bounded() {
        assert_eq!(valid_client_id(" transcripts ").unwrap(), "transcripts");
        assert_eq!(valid_client_id(" ").unwrap_err(), "client_id_required");
        assert_eq!(valid_client_id(&"x".repeat(129)).unwrap_err(), "client_id_too_long");
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(constant_time_equal("abc", "abc"));
        assert!(!constant_time_equal("abc", "abd"));
        assert!(!constant_time_equal("abc", "abcd"));
    }

    #[test]
    fn capabilities_contain_only_control_plane_routes() {
        let payload = capabilities();
        assert_eq!(payload["authenticated"], true);
        assert!(payload["authenticated_endpoints"].as_array().is_some_and(|items| items.len() >= 50));
    }

    #[test]
    fn sse_frame_is_parseable() {
        let frame = sse_frame("agent-hook", &json!({ "agent": "codex" }));
        assert!(frame.starts_with("event: agent-hook\ndata: "));
        assert!(frame.ends_with("\n\n"));
        assert!(frame.contains("\"agent\":\"codex\""));
    }

    use std::io::Read;

    /// Os testes abaixo falam com o cofre real (Credential Manager) e com o desafio de pairing,
    /// que são globais do processo: em paralelo um sobrescreve o outro. O lock serializa só eles.
    static CREDENTIAL_TESTS: Mutex<()> = Mutex::new(());

    /// Requisição HTTP crua com método e auth à escolha. O `http_request` da suíte de pairing é o
    /// atalho de POST sem token em cima desta. Devolve a resposta inteira (cabeçalho e corpo) porque
    /// o contrato de auth inclui o desafio do esquema (`WWW-Authenticate`), que só existe no
    /// cabeçalho — checar apenas o status deixaria o desafio sem teste.
    fn http_call_raw(
        port: u16,
        method: &str,
        path: &str,
        auth_header: Option<&str>,
        body: Option<&str>,
    ) -> String {
        let body_text = body.unwrap_or("");
        let auth = auth_header
            .map(|header| format!("Authorization: {header}\r\n"))
            .unwrap_or_default();
        let raw_request = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_text}",
            body_text.len()
        );
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to control server");
        stream.write_all(raw_request.as_bytes()).expect("write request");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).expect("read response");
        raw
    }

    fn status_of(raw: &str) -> u16 {
        raw.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("status code")
    }

    fn body_of(raw: &str) -> String {
        raw.split_once("\r\n\r\n")
            .map(|(_, body)| body.trim().to_string())
            .unwrap_or_default()
    }

    fn http_call(
        port: u16,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        let header = token.map(|token| format!("Bearer {token}"));
        let raw = http_call_raw(port, method, path, header.as_deref(), body);
        (status_of(&raw), body_of(&raw))
    }

    fn http_request(port: u16, path: &str, body: Option<&str>) -> (u16, String) {
        http_call(port, "POST", path, None, body)
    }

    /// Servidor de controle real (porta efêmera) atendendo pairing, events, fs, git, worktrees e
    /// validação. O despacho repete os ramos do `handle_request`, que pede um `AppHandle` que o teste
    /// não monta; tudo o mais é o de produção — inclusive o 401 de rota autenticada sem token.
    fn control_server() -> u16 {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind control server");
        let port = server.server_addr().to_ip().expect("ip listener").port();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let method = request.method().to_string();
                let url = request.url().to_string();
                let path = endpoint_path(&url).to_string();
                if let Some(response) = pairing_route(&method, &path, &mut request) {
                    let _ = request.respond(response);
                    continue;
                }
                let mut request = match events_route(&method, &path, request) {
                    Some(restored) => restored,
                    None => continue,
                };
                let Some(token) = bearer_token(&request) else {
                    let _ = request.respond(unauthorized_response());
                    continue;
                };
                if state().authenticate(token).is_err() {
                    let _ = request.respond(unauthorized_response());
                    continue;
                }
                let response = if path.starts_with("/control/v1/fs/") || path == "/control/v1/fs" {
                    filesystem_route(&method, &path, &url, &mut request)
                } else if path.starts_with("/control/v1/git/")
                    || path == "/control/v1/worktrees"
                    || path.starts_with("/control/v1/worktrees/")
                {
                    git_route(&method, &path, &url, &mut request)
                } else if path.starts_with("/control/v1/validation/") {
                    validation_route(&method, &path, &mut request)
                } else if let Some(response) = auth_route(&method, &path, token) {
                    // as rotas de sessão são as de produção: a suíte de auth não pode testar cópia
                    Some(response)
                } else {
                    None
                }
                .unwrap_or_else(|| error_response(404, "control_route_not_found"));
                let _ = request.respond(response);
            }
        });
        port
    }

    /// Índice da `n`-ésima ocorrência (a partir de 1) — separa os frames de cada rodada.
    fn nth_at(buffer: &str, needle: &str, n: usize) -> usize {
        buffer
            .match_indices(needle)
            .nth(n - 1)
            .unwrap_or_else(|| panic!("{n}ª ocorrência de {needle} não apareceu: {buffer}"))
            .0
    }

    /// Valor string de `key` no primeiro objeto depois de `needle` — só para casar o `run_id` entre
    /// os dois frames de uma rodada sem trazer um parser JSON para dentro do teste.
    fn string_field_after(buffer: &str, needle: &str, key: &str) -> String {
        let scope = buffer
            .split(needle)
            .nth(1)
            .unwrap_or_else(|| panic!("{needle} não apareceu no stream: {buffer}"));
        let needle = format!("\"{key}\":\"");
        scope
            .split(&needle)
            .nth(1)
            .unwrap_or_else(|| panic!("{needle} não apareceu depois de {scope}"))
            .split('"')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn pairing_body(client_id: &str, code: &str) -> String {
        json!({ "client_id": client_id, "pairing_code": code }).to_string()
    }

    fn window_code() -> String {
        state().pairing_pending().expect("pending payload")["code"]
            .as_str()
            .expect("code visible to the window")
            .to_string()
    }

    fn expire_window() {
        let mut pairing = state().pairing.lock().expect("lock");
        let challenge = pairing.as_mut().expect("challenge");
        challenge.expires_at = SystemTime::now() - Duration::from_secs(1);
    }

    /// Abre um stream SSE real: socket de verdade e cabeçalho HTTP escrito à mão, como o resto da
    /// suíte. O stream não fecha (keep-alive de 30s), daí o timeout curto de leitura.
    fn sse_connect(port: u16, token: &str) -> std::net::TcpStream {
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to control server");
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("read timeout");
        let raw = format!(
            "GET /control/v1/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n\r\n"
        );
        stream.write_all(raw.as_bytes()).expect("write sse request");
        stream
    }

    /// Acumula do stream até todos os `needles` aparecerem — e até o buffer terminar numa fronteira de
    /// quadro (`\n\n`), senão a última needle pode ser encontrada no meio de um quadro que ainda não
    /// chegou inteiro e a asserção sobre o payload dela falha sem o app ter errado. Dois frames podem
    /// chegar no mesmo recv, então a asserção de ordem é feita no buffer acumulado.
    fn sse_read_until_all(
        stream: &mut std::net::TcpStream,
        needles: &[&str],
        deadline: std::time::Instant,
    ) -> String {
        let mut buffer = String::new();
        let mut chunk = [0u8; 4096];
        while std::time::Instant::now() < deadline
            && (needles.iter().any(|needle| !buffer.contains(needle))
                || !buffer.ends_with("\n\n"))
        {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => buffer.push_str(&String::from_utf8_lossy(&chunk[..read])),
                Err(_) => continue,
            }
        }
        buffer
    }

    /// Lê tudo o que chegar dentro de uma janela de tempo e devolve o acumulado. É o que permite
    /// afirmar ausência: depois do evento positivo o teste deixa o stream quieto e só então procura o
    /// que não podia sair. O read timeout curto do socket faz a janela terminar sozinha.
    fn sse_read_window(stream: &mut std::net::TcpStream, window: Duration) -> String {
        let deadline = std::time::Instant::now() + window;
        let mut buffer = String::new();
        let mut chunk = [0u8; 4096];
        while std::time::Instant::now() < deadline {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => buffer.push_str(&String::from_utf8_lossy(&chunk[..read])),
                Err(_) => continue,
            }
        }
        buffer
    }

    /// Parea de verdade (start → aprovação na janela → complete) e devolve o token.
    fn pair_for_token(port: u16) -> String {
        let start = json!({ "client_id": "transcripts" }).to_string();
        let (status, _) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200);
        state().pairing_decide(true).expect("approve");
        let (status, body) = http_request(
            port,
            "/control/v1/pairing/complete",
            Some(&pairing_body("transcripts", &window_code())),
        );
        assert_eq!(status, 200);
        serde_json::from_str::<Value>(&body).expect("json body")["access_token"]
            .as_str()
            .expect("access token")
            .to_string()
    }

    /// Step 2 da Task 4 nas rotas de fs e validação: cada mutação real aparece no SSE — e aparece sem
    /// o conteúdo. Servidor, socket, token, rota, validação (processo de verdade) e stream são os de
    /// produção; só o despacho é repetido aqui, porque o `handle_request` pede um `AppHandle` que o
    /// teste não monta. Os ramos copiados são os mesmos do `handle_request`, incluindo o auth.
    #[test]
    fn routed_events_reach_the_sse_without_content() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = control_server();

        // o auth real vale para estas rotas: sem token, 401 e nenhum evento
        let (status, _) = http_call(
            port,
            "PUT",
            "/control/v1/fs/write",
            None,
            Some(&json!({ "path": "x.txt", "content": "y" }).to_string()),
        );
        assert_eq!(status, 401, "rota de fs sem token precisa responder 401");

        let token = pair_for_token(port);
        let mut stream = sse_connect(port, &token);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let opening = sse_read_until_all(&mut stream, &["event: ready"], deadline);
        assert!(
            opening.starts_with("HTTP/1.1 200"),
            "SSE precisa abrir com 200: {opening}"
        );

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("alethe-control-events-{suffix}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let sub = dir.join("sub");
        let alvo = dir.join("alvo.txt");
        let movido = dir.join("movido.txt");
        let dir_text = dir.to_string_lossy().to_string();
        let sub_text = sub.to_string_lossy().to_string();
        let alvo_text = alvo.to_string_lossy().to_string();
        let movido_text = movido.to_string_lossy().to_string();
        // o marcador entra no arquivo, na linha de comando e na saída da validação: se vazar para o
        // stream, ele aparece em algum dos três caminhos
        let segredo = format!("SEGREDO-DO-USUARIO-{}", nanoid::nanoid!(8));

        let (status, _) = http_call(
            port,
            "POST",
            "/control/v1/fs/mkdir",
            Some(&token),
            Some(&json!({ "path": sub_text }).to_string()),
        );
        assert_eq!(status, 201);
        let (status, _) = http_call(
            port,
            "PUT",
            "/control/v1/fs/write",
            Some(&token),
            Some(&json!({ "path": alvo_text, "content": segredo }).to_string()),
        );
        assert_eq!(status, 200);
        let (status, _) = http_call(
            port,
            "POST",
            "/control/v1/fs/move",
            Some(&token),
            Some(&json!({ "path": alvo_text, "destination": movido_text }).to_string()),
        );
        assert_eq!(status, 200);
        let (status, _) = http_call(
            port,
            "DELETE",
            "/control/v1/fs",
            Some(&token),
            Some(&json!({ "path": movido_text }).to_string()),
        );
        assert_eq!(status, 200);

        // três rodadas reais: uma que falha (e devolve a saída do comando ao chamador), uma que passa
        // e uma que nem chega a executar
        let (status, failing_body) = http_call(
            port,
            "POST",
            "/control/v1/validation/run",
            Some(&token),
            Some(
                &json!({ "cwd": dir_text, "commands": [format!("echo {segredo} & exit 1")] })
                    .to_string(),
            ),
        );
        assert_eq!(status, 200);
        // o conteúdo existe e volta para quem pediu: na falha o `output` é o stdout/stderr real. Sem
        // isto, a asserção de que o marcador não aparece no stream poderia passar por vacuidade.
        assert!(
            failing_body.contains(&segredo),
            "a rodada que falha precisa devolver a saída do comando ao chamador: {failing_body}"
        );
        let (status, _) = http_call(
            port,
            "POST",
            "/control/v1/validation/run",
            Some(&token),
            Some(&json!({ "cwd": dir_text, "commands": ["echo ok"] }).to_string()),
        );
        assert_eq!(status, 200);
        let (status, _) = http_call(
            port,
            "POST",
            "/control/v1/validation/run",
            Some(&token),
            Some(&json!({ "cwd": dir.join("nao-existe").to_string_lossy(), "commands": ["echo x"] }).to_string()),
        );
        assert_eq!(status, 400);

        let frames = sse_read_until_all(
            &mut stream,
            &[
                "\"action\":\"mkdir\"",
                "\"action\":\"write\"",
                "\"action\":\"move\"",
                "\"action\":\"delete\"",
                "\"error\":\"directory_not_found\"",
            ],
            deadline,
        );

        // as quatro mutações de disco, com o caminho que mudou. `json!` porque o caminho no frame
        // chega escapado (`C:\\Users\\...`), que é o encoding real do stream.
        for (action, path) in [
            ("mkdir", sub_text.as_str()),
            ("write", alvo_text.as_str()),
            ("move", alvo_text.as_str()),
            ("delete", movido_text.as_str()),
        ] {
            let frame = format!("\"action\":\"{action}\"");
            let at = frames
                .find(&frame)
                .unwrap_or_else(|| panic!("{frame} não chegou no SSE: {frames}"));
            let expected = json!(path).to_string();
            assert!(
                frames[at..].contains(&expected),
                "o evento {action} precisa dizer qual caminho mudou ({expected}): {frames}"
            );
        }
        assert!(
            frames.contains(&format!("\"destination\":{}", json!(movido_text))),
            "o move precisa levar o destino: {frames}"
        );
        assert_eq!(
            frames.matches("event: file.changed").count(),
            4,
            "cada mutação gera exatamente um evento: {frames}"
        );

        // started antes de completed, e os dois casados pelo mesmo run_id
        for round in 1..=3 {
            let started_at = nth_at(&frames, "event: validation.started", round);
            let completed_at = nth_at(&frames, "event: validation.completed", round);
            assert!(
                started_at < completed_at,
                "started precisa vir antes de completed na rodada {round}: {frames}"
            );
            assert_eq!(
                string_field_after(&frames[started_at..], "validation.started", "run_id"),
                string_field_after(&frames[completed_at..], "validation.completed", "run_id"),
                "o run_id precisa casar started/completed na rodada {round}: {frames}"
            );
        }
        let first_round = &frames[nth_at(&frames, "event: validation.started", 1)
            ..nth_at(&frames, "event: validation.completed", 2)];
        assert!(
            first_round.contains("\"command_count\":1"),
            "started precisa dizer quantos comandos foram configurados: {first_round}"
        );
        assert!(
            first_round.contains("\"success\":false") && first_round.contains("\"ran_any_command\":true"),
            "a rodada que falhou precisa levar o veredito, não o texto do comando: {first_round}"
        );
        assert!(
            first_round.contains("\"duration_ms\":"),
            "completed precisa levar a duração: {first_round}"
        );
        let second_round = &frames[nth_at(&frames, "event: validation.started", 2)
            ..nth_at(&frames, "event: validation.completed", 3)];
        assert!(
            second_round.contains("\"success\":true") && second_round.contains("\"ran_any_command\":true"),
            "a rodada que passou precisa levar success:true: {second_round}"
        );
        // a rodada que falhou antes de executar ainda fecha o ciclo
        let third_round = &frames[nth_at(&frames, "event: validation.started", 3)..];
        assert!(
            third_round.contains("\"error\":\"directory_not_found\"")
                && third_round.contains("\"success\":false"),
            "a rodada que não executou precisa fechar o ciclo com o motivo: {third_round}"
        );

        // o conteúdo nunca sai: nem o do arquivo, nem a linha de comando, nem a saída da validação
        assert!(
            !frames.contains(&segredo),
            "conteúdo do usuário vazou para o stream: {frames}"
        );
        for forbidden in ["\"stage\"", "\"output\"", "\"content\"", "\"stdout\""] {
            assert!(
                !frames.contains(forbidden),
                "chave de conteúdo {forbidden} não pode sair no stream: {frames}"
            );
        }

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
        state().revoke(&token).expect("revoke test session");
    }

    /// Frame SSE que contém `needle`, do `event:` até o fim do frame — para afirmar o payload daquele
    /// evento e não o do seguinte (todos os eventos de git carregam o mesmo repo).
    fn sse_frame_with(frames: &str, needle: &str) -> String {
        let at = nth_at(frames, needle, 1);
        let start = frames[..at].rfind("event: ").unwrap_or(at);
        let end = frames[at..]
            .find("\n\n")
            .map(|offset| at + offset)
            .unwrap_or(frames.len());
        frames[start..end].to_string()
    }

    /// O `data` do frame daquele tipo de evento, já como JSON — deixa afirmar envelope e payload
    /// separadamente (os dois carregam `agent_id`, por exemplo).
    fn sse_event_json(frames: &str, event_type: &str) -> Value {
        let frame = frames
            .split(&format!("event: {event_type}"))
            .nth(1)
            .unwrap_or_else(|| panic!("evento {event_type} não chegou no SSE: {frames}"));
        let data = frame
            .split_once("data: ")
            .unwrap_or_else(|| panic!("frame de {event_type} sem data: {frame}"))
            .1
            .split("\n\n")
            .next()
            .unwrap_or_default();
        serde_json::from_str::<Value>(data)
            .unwrap_or_else(|error| panic!("data de {event_type} não é JSON ({error}): {data}"))
    }

    /// Roda um comando de git de verdade no repo do teste.
    fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
        let output = crate::git_control::checked_output(dir, args)
            .unwrap_or_else(|error| panic!("git {args:?} falhou: {error}"));
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// Step 2 da Task 4 no git: cada rota que mexe no repositório conta o que fez no SSE, com o repo —
    /// e sem o conteúdo (mensagem de commit, saída do git, lista de caminhos). Repo, remote, rotas,
    /// auth e stream são reais; o remote é um bare local, então push/pull correm de verdade e offline.
    #[test]
    fn git_routes_announce_what_changed_without_content() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = control_server();
        let token = pair_for_token(port);
        let mut stream = sse_connect(port, &token);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let opening = sse_read_until_all(&mut stream, &["event: ready"], deadline);
        assert!(
            opening.starts_with("HTTP/1.1 200"),
            "SSE precisa abrir com 200: {opening}"
        );

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("alethe-control-git-{suffix}"));
        let remote = std::env::temp_dir().join(format!("alethe-control-git-remote-{suffix}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::create_dir_all(&remote).expect("temp remote dir");
        git_in(&dir, &["init"]);
        git_in(&dir, &["config", "user.name", "Alethe Test"]);
        git_in(&dir, &["config", "user.email", "alethe@example.invalid"]);
        std::fs::write(dir.join("um.txt"), "um\n").expect("write tracked file");
        git_in(&dir, &["add", "um.txt"]);
        git_in(&dir, &["commit", "-m", "inicial"]);
        let main_branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
        // bare local: push/pull reais sem rede
        let remote_slash = remote.to_string_lossy().replace('\\', "/");
        git_in(&remote, &["init", "--bare"]);
        git_in(&dir, &["remote", "add", "origin", &remote_slash]);

        // um commit que só existe no ramo paralelo: é o que o cherry-pick traz e o revert desfaz
        git_in(&dir, &["checkout", "-b", "alethe/later"]);
        std::fs::write(dir.join("do-ramo.txt"), "do ramo\n").expect("write branch file");
        git_in(&dir, &["add", "do-ramo.txt"]);
        git_in(&dir, &["commit", "-m", "do ramo paralelo"]);
        let branch_hash = git_in(&dir, &["rev-parse", "HEAD"]);
        git_in(&dir, &["checkout", &main_branch]);
        let main_hash = git_in(&dir, &["rev-parse", "HEAD"]);

        let dir_text = dir.to_string_lossy().to_string();
        let alvo_text = dir.join("alvo.txt").to_string_lossy().to_string();
        let rascunho_text = dir.join("rascunho.txt").to_string_lossy().to_string();
        let marker = format!("MENSAGEM-DE-COMMIT-{}", nanoid::nanoid!(8));
        let git_call = |path: &str, body: Value| {
            http_call(
                port,
                "POST",
                path,
                Some(&token),
                Some(&body.to_string()),
            )
        };

        let (status, _) = git_call("/control/v1/git/init", json!({ "path": dir_text }));
        assert_eq!(status, 201);

        let (status, _) = http_call(
            port,
            "PUT",
            "/control/v1/fs/write",
            Some(&token),
            Some(&json!({ "path": alvo_text, "content": "conteudo do alvo\n" }).to_string()),
        );
        assert_eq!(status, 200);
        let (status, _) = git_call(
            "/control/v1/git/stage",
            json!({ "repo_root": dir_text, "paths": ["alvo.txt"] }),
        );
        assert_eq!(status, 200);
        let (status, commit_body) = git_call(
            "/control/v1/git/commit",
            json!({ "repo_root": dir_text, "message": marker }),
        );
        assert_eq!(status, 200);
        // o git devolve a mensagem no stdout da própria rota: o conteúdo existe e voltou ao chamador,
        // então a ausência dele no stream não é vacuidade.
        assert!(
            commit_body.contains(&marker),
            "o commit precisa devolver a saída do git ao chamador: {commit_body}"
        );
        let (status, _) = git_call(
            "/control/v1/git/unstage",
            json!({ "repo_root": dir_text, "paths": ["alvo.txt"] }),
        );
        assert_eq!(status, 200);
        let (status, _) = http_call(
            port,
            "PUT",
            "/control/v1/fs/write",
            Some(&token),
            Some(&json!({ "path": rascunho_text, "content": "rascunho\n" }).to_string()),
        );
        assert_eq!(status, 200);
        let (status, _) = git_call(
            "/control/v1/git/discard",
            json!({ "repo_root": dir_text, "paths": ["rascunho.txt"], "untracked": true }),
        );
        assert_eq!(status, 200);
        let (status, _) = git_call("/control/v1/git/push", json!({ "path": dir_text }));
        assert_eq!(status, 200);
        let (status, _) = git_call("/control/v1/git/pull", json!({ "path": dir_text }));
        assert_eq!(status, 200);
        let (status, _) = git_call(
            "/control/v1/git/branch",
            json!({ "repo": dir_text, "hash": branch_hash, "branch_name": "alethe/teste" }),
        );
        assert_eq!(status, 201);
        let (status, _) = git_call(
            "/control/v1/git/cherry-pick",
            json!({ "repo": dir_text, "hash": branch_hash }),
        );
        assert_eq!(status, 200);
        let (status, _) = git_call(
            "/control/v1/git/revert",
            json!({ "repo": dir_text, "hash": branch_hash }),
        );
        assert_eq!(status, 200);
        let (status, _) = git_call(
            "/control/v1/git/reset",
            json!({ "repo": dir_text, "hash": main_hash, "mode": "hard" }),
        );
        assert_eq!(status, 200);

        let actions = [
            "init", "stage", "unstage", "discard", "commit", "pull", "push", "branch", "cherry-pick",
            "revert", "reset",
        ];
        let needles: Vec<String> = actions
            .iter()
            .map(|action| format!("\"action\":\"{action}\""))
            .collect();
        let frames = sse_read_until_all(
            &mut stream,
            &needles.iter().map(String::as_str).collect::<Vec<_>>(),
            deadline,
        );

        let repo_json = json!(dir_text).to_string();
        // o init canonicaliza (é o root que o git devolve), os outros ecoam o caminho recebido
        let canonical_json = json!(crate::worktrees::git_arg(
            &std::fs::canonicalize(&dir).expect("canonical do repo")
        ))
        .to_string();
        for (action, needle) in actions.iter().zip(needles.iter()) {
            assert_eq!(
                frames.matches(needle.as_str()).count(),
                1,
                "cada {action} gera exatamente um evento: {frames}"
            );
            let frame = sse_frame_with(&frames, needle);
            assert!(
                frame.contains("event: git.changed"),
                "o evento precisa ser git.changed ({action}): {frame}"
            );
            let repo = if *action == "init" {
                &canonical_json
            } else {
                &repo_json
            };
            assert!(
                frame.contains(&format!("\"repo\":{repo}")),
                "o evento precisa dizer em que repo ({action}): {frame}"
            );
        }
        assert!(
            sse_frame_with(&frames, "\"action\":\"stage\"").contains("\"path_count\":1"),
            "stage precisa dizer quantos caminhos foram para o índice: {frames}"
        );
        assert!(
            sse_frame_with(&frames, "\"action\":\"reset\"").contains("\"mode\":\"hard\""),
            "reset precisa dizer o modo: {frames}"
        );

        assert!(
            !frames.contains(&marker),
            "mensagem de commit não pode ir para o stream: {frames}"
        );
        for forbidden in ["\"message\"", "\"output\"", "\"paths\""] {
            assert!(
                !frames.contains(forbidden),
                "chave de conteúdo {forbidden} não pode sair no stream: {frames}"
            );
        }

        std::fs::remove_dir_all(&remote).expect("cleanup temp remote");
        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
        state().revoke(&token).expect("revoke test session");
    }

    /// Step 2 da Task 4 no worktree: montar e remover a cópia de trabalho de um agente conta no SSE.
    /// Repo temporário real, `git worktree` de verdade, rotas, auth e stream reais.
    #[test]
    fn worktree_routes_announce_creation_and_removal() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = control_server();
        let token = pair_for_token(port);
        let mut stream = sse_connect(port, &token);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let opening = sse_read_until_all(&mut stream, &["event: ready"], deadline);
        assert!(
            opening.starts_with("HTTP/1.1 200"),
            "SSE precisa abrir com 200: {opening}"
        );

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("alethe-control-worktree-{suffix}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        git_in(&dir, &["init"]);
        git_in(&dir, &["config", "user.name", "Alethe Test"]);
        git_in(&dir, &["config", "user.email", "alethe@example.invalid"]);
        std::fs::write(dir.join("um.txt"), "um\n").expect("write tracked file");
        git_in(&dir, &["add", "um.txt"]);
        git_in(&dir, &["commit", "-m", "inicial"]);

        let dir_text = dir.to_string_lossy().to_string();
        let (status, body) = http_call(
            port,
            "POST",
            "/control/v1/worktrees",
            Some(&token),
            Some(
                &json!({ "repo": dir_text, "agent_id": "agente-teste", "mode": "gitWorktree" })
                    .to_string(),
            ),
        );
        assert_eq!(status, 201, "provision falhou: {body}");
        let worktree_path = serde_json::from_str::<Value>(&body).expect("json body")["worktree"]["path"]
            .as_str()
            .expect("caminho da cópia de trabalho")
            .to_string();
        assert!(
            std::path::Path::new(&worktree_path).is_dir(),
            "a cópia de trabalho precisa existir no disco: {worktree_path}"
        );

        // a rota de remoção recebe o repo na query, então o caminho vai percent-encoded
        let repo_query = dir_text.replace('\\', "%5C").replace(' ', "%20");
        let (status, body) = http_call(
            port,
            "DELETE",
            &format!("/control/v1/worktrees/agente-teste?repo={repo_query}&force=1"),
            Some(&token),
            None,
        );
        assert_eq!(status, 200, "remoção falhou: {body}");
        assert!(
            !std::path::Path::new(&worktree_path).exists(),
            "a cópia de trabalho precisa ter saído do disco: {worktree_path}"
        );

        let frames = sse_read_until_all(
            &mut stream,
            &["event: worktree.created", "event: worktree.removed"],
            deadline,
        );
        let created = sse_event_json(&frames, "worktree.created");
        assert_eq!(
            created["agent_id"], "agente-teste",
            "o envelope do bus precisa levar o agente: {created}"
        );
        assert_eq!(
            created["data"]["agent_id"], "agente-teste",
            "o payload precisa dizer de que agente é a cópia: {created}"
        );
        assert_eq!(
            created["data"]["mode"], "gitWorktree",
            "o payload precisa dizer em que modo a cópia foi feita: {created}"
        );
        assert_eq!(
            created["data"]["repo"], dir_text,
            "o payload precisa dizer de que repo é a cópia: {created}"
        );
        let removed = sse_event_json(&frames, "worktree.removed");
        assert_eq!(removed["data"]["agent_id"], "agente-teste", "{removed}");
        assert_eq!(removed["data"]["repo"], dir_text, "{removed}");
        assert_eq!(
            removed["data"]["force"], true,
            "a remoção precisa dizer se o descarte foi forçado: {removed}"
        );
        assert!(
            !frames.contains(&json!(worktree_path).to_string()),
            "o caminho da cópia de trabalho fica na resposta, não no evento: {frames}"
        );
        assert_eq!(
            frames.matches("event: worktree.created").count(),
            1,
            "exatamente um evento de criação: {frames}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
        state().revoke(&token).expect("revoke test session");
    }

    /// Step 1 da Task 4: o stream SSE precisa carregar o ciclo de vida que só existe no event bus
    /// (scheduler, supervisor, rotas). Sem a ponte o stream nasce quase vazio — este teste é o gate
    /// de que a ponte existe, preserva a ordem do bus e entrega o envelope com o data inteiro.
    #[test]
    fn sse_stream_bridges_the_event_bus_with_envelopes() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind control server");
        let port = server.server_addr().to_ip().expect("ip listener").port();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let method = request.method().to_string();
                let url = request.url().to_string();
                let path = endpoint_path(&url).to_string();
                if let Some(response) = pairing_route(&method, &path, &mut request) {
                    let _ = request.respond(response);
                    continue;
                }
                let request = match events_route(&method, &path, request) {
                    Some(restored) => restored,
                    None => continue,
                };
                let _ = request.respond(error_response(404, "control_route_not_found"));
            }
        });

        let token = pair_for_token(port);
        let mut stream = sse_connect(port, &token);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let opening = sse_read_until_all(&mut stream, &["event: ready"], deadline);
        assert!(
            opening.starts_with("HTTP/1.1 200"),
            "SSE precisa abrir com 200: {opening}"
        );
        assert!(
            opening.contains("Content-Type: text/event-stream"),
            "SSE precisa ser text/event-stream: {opening}"
        );

        // eventos da lista do stream (os mesmos do ciclo de vida real): o processo inteiro
        // compartilha o mesmo bus e os testes rodam em paralelo, então nada de tipo inventado
        emit_control_event(
            "agent.working",
            Some("agent-1".to_string()),
            json!({ "agent_id": "agent-1", "source": "send", "message_bytes": 7 }),
        );
        crate::event_bus::publish_event_simple(
            "terminal.output",
            "sched-test",
            None,
            Some("agent-1".to_string()),
            json!({ "bytes": 12, "dropped_bytes": 0 }),
        );

        let frames = sse_read_until_all(
            &mut stream,
            &["event: agent.working", "event: terminal.output"],
            deadline,
        );
        let first_at = frames
            .find("event: agent.working")
            .unwrap_or_else(|| panic!("primeiro evento não chegou no SSE: {frames}"));
        let second_at = frames
            .find("event: terminal.output")
            .unwrap_or_else(|| panic!("segundo evento não chegou no SSE: {frames}"));
        assert!(
            first_at < second_at,
            "a ponte precisa preservar a ordem do bus: {frames}"
        );
        assert!(
            frames.contains("\"correlation_id\":\"ctrl-"),
            "evento do control plane precisa levar o envelope com correlation_id: {frames}"
        );
        assert!(
            frames.contains("\"message_bytes\":7") && frames.contains("\"bytes\":12"),
            "o data do bus precisa chegar inteiro: {frames}"
        );
        assert!(
            frames.contains("\"agent_id\":\"agent-1\""),
            "o envelope do bus precisa manter agent_id: {frames}"
        );

        state().revoke(&token).expect("revoke test session");
    }

    /// O outro lado da fronteira do stream: o bus carrega evento interno com texto do usuário
    /// (`task_title` do scheduler, `subject` do planejamento, `error` dos `TaskFailed`) e nada disso
    /// pode chegar ao consumidor externo, que persiste o que recebe. O teste prova as duas pontas na
    /// mesma rodada: o evento interno **entrou no bus** (o assinante do teste o recebe) e **não** saiu
    /// no stream, enquanto um evento da lista saiu. Sem a primeira metade o teste passaria por
    /// vacuidade — bastaria a emissão não ter acontecido.
    #[test]
    fn internal_bus_events_with_user_text_do_not_cross_the_stream() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind control server");
        let port = server.server_addr().to_ip().expect("ip listener").port();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let method = request.method().to_string();
                let url = request.url().to_string();
                let path = endpoint_path(&url).to_string();
                if let Some(response) = pairing_route(&method, &path, &mut request) {
                    let _ = request.respond(response);
                    continue;
                }
                let request = match events_route(&method, &path, request) {
                    Some(restored) => restored,
                    None => continue,
                };
                let _ = request.respond(error_response(404, "control_route_not_found"));
            }
        });

        let token = pair_for_token(port);
        let mut stream = sse_connect(port, &token);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let opening = sse_read_until_all(&mut stream, &["event: ready"], deadline);
        assert!(
            opening.starts_with("HTTP/1.1 200"),
            "SSE precisa abrir com 200: {opening}"
        );

        // o assinante do teste vê o mesmo bus que a ponte: é ele que prova que o evento sujo existiu
        let mut bus = crate::event_bus::subscribe();
        let titulo = "consertar o login do cliente acme";
        crate::event_bus::publish_event_simple(
            "AgentSpawnRequested",
            "sched-test",
            None,
            Some("agent-1".to_string()),
            json!({ "agent_id": "agent-1", "worktree_path": "D:\\wt", "task_title": titulo }),
        );
        crate::event_bus::publish_event_simple(
            "TaskCompleted",
            "sched-test",
            None,
            None,
            json!({}),
        );
        let visto_no_bus = bus.blocking_recv().expect("evento no bus");
        assert_eq!(
            visto_no_bus.event_type, "AgentSpawnRequested",
            "o evento interno precisa ter entrado no bus para o teste valer"
        );
        assert_eq!(
            visto_no_bus.data["task_title"], titulo,
            "o bus carrega o texto do usuário: é ele que não pode atravessar"
        );

        emit_control_event(
            "agent.started",
            Some("agent-1".to_string()),
            json!({ "agent_id": "agent-1", "agent": "cmd", "status": "started", "source": "teste" }),
        );
        let frames = sse_read_until_all(&mut stream, &["event: agent.started"], deadline);
        assert!(
            frames.contains("event: agent.started"),
            "evento da lista precisa sair no stream: {frames}"
        );

        // o evento interno foi publicado antes do da lista e a ponte entrega na ordem do bus, então
        // quando o da lista aparece o interno já teria aparecido — a janela extra é para o caso de o
        // frame do interno estar a caminho
        let depois = sse_read_window(&mut stream, Duration::from_millis(700));
        let tudo = format!("{frames}{depois}");
        for proibido in ["AgentSpawnRequested", "TaskCompleted", "task_title", titulo] {
            assert!(
                !tudo.contains(proibido),
                "evento interno atravessou o stream ('{proibido}'): {tudo}"
            );
        }

        state().revoke(&token).expect("revoke test session");
    }

    #[test]
    fn pairing_needs_a_window_approval_and_the_code_is_one_time() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind control server");
        let port = server.server_addr().to_ip().expect("ip listener").port();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let method = request.method().to_string();
                let url = request.url().to_string();
                let path = endpoint_path(&url).to_string();
                let response = pairing_route(&method, &path, &mut request)
                    .unwrap_or_else(|| error_response(404, "control_route_not_found"));
                let _ = request.respond(response);
            }
        });

        let start = json!({ "client_id": "transcripts" }).to_string();

        // 1. the asking client is told approval is required and never receives the code
        let (status, body) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200);
        let payload: Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(payload["approval_required"], true);
        assert_eq!(payload["client_id"], "transcripts");
        assert!(payload.get("pairing_code").is_none(), "start leaked the pairing code over HTTP");

        // 2. the code exists only on the window side
        let pending = state().pairing_pending().expect("pending payload");
        assert_eq!(pending["pending"], true);
        assert_eq!(pending["status"], "pending");
        assert_eq!(window_code().len(), 32);

        // 3. completing before the human approves is refused
        let pending_body = pairing_body("transcripts", &window_code());
        let (status, body) = http_request(port, "/control/v1/pairing/complete", Some(&pending_body));
        assert_eq!(status, 400);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["error"],
            "pairing_approval_pending"
        );

        // 4. a denied request can never mint a token, even with the right code
        state().pairing_decide(false).expect("deny");
        let (status, body) = http_request(port, "/control/v1/pairing/complete", Some(&pending_body));
        assert_eq!(status, 400);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["error"],
            "pairing_denied"
        );

        // 5. an approved request pairs exactly once
        let (status, _) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200);
        let approved_code = window_code();
        let approved_body = pairing_body("transcripts", &approved_code);
        state().pairing_decide(true).expect("approve");
        let (status, body) = http_request(port, "/control/v1/pairing/complete", Some(&approved_body));
        assert_eq!(status, 200);
        let payload: Value = serde_json::from_str(&body).expect("json body");
        let token = payload["access_token"].as_str().expect("access token").to_string();
        assert_eq!(payload["token_type"], "Bearer");
        assert!(state().authenticate(&token).is_ok(), "minted token must authenticate");

        // 6. the same code cannot be replayed
        let (status, body) = http_request(port, "/control/v1/pairing/complete", Some(&approved_body));
        assert_eq!(status, 400);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["error"],
            "pairing_not_started"
        );

        // 7. an expired request is refused to the client, even with the right code
        let (status, _) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200);
        let expired_code = window_code();
        expire_window();
        let (status, body) = http_request(
            port,
            "/control/v1/pairing/complete",
            Some(&pairing_body("transcripts", &expired_code)),
        );
        assert_eq!(status, 400);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["error"],
            "pairing_expired"
        );
        // the refused completion already dropped it, so nothing is left to approve
        assert_eq!(
            state().pairing_pending().expect("pending payload")["pending"],
            false
        );

        // 8. the window side cannot approve an expired request either
        let (status, _) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200);
        expire_window();
        assert_eq!(
            state().pairing_decide(true).expect_err("expired request cannot be approved"),
            "pairing_expired"
        );
        assert_eq!(
            state().pairing_pending().expect("pending payload")["pending"],
            false
        );

        // the test session lives in the real credential store; take it back out
        state().revoke(&token).expect("revoke test session");
    }

    /// Suíte de auth, parte 1: o que a porta de entrada recusa. Roda contra o listener real (porta
    /// efêmera) e o caminho de auth de produção — o mesmo que atende o cliente —, com socket real.
    /// O desafio do esquema entra na asserção porque um 401 sem `WWW-Authenticate` deixa o cliente
    /// sem saber que precisa de Bearer; e o token desconhecido tem o formato plausível (48 chars),
    /// para o teste não passar por acidente ao recusar lixo.
    #[test]
    fn the_unauthorized_contract_holds_over_real_http() {
        let port = control_server();

        let raw = http_call_raw(port, "GET", "/control/v1/auth/session", None, None);
        assert_eq!(status_of(&raw), 401, "rota autenticada sem token: {raw}");
        assert!(
            raw.to_lowercase().contains("www-authenticate: bearer"),
            "o 401 precisa anunciar o esquema: {raw}"
        );
        assert!(raw.contains("authentication_required"), "{raw}");

        let raw = http_call_raw(
            port,
            "GET",
            "/control/v1/auth/session",
            Some("Token nao-e-bearer"),
            None,
        );
        assert_eq!(status_of(&raw), 401, "esquema errado não pode virar token: {raw}");

        let desconhecido = nanoid::nanoid!(48);
        let (status, body) = http_call(port, "GET", "/control/v1/auth/session", Some(&desconhecido), None);
        assert_eq!(status, 401, "token desconhecido com formato válido: {body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["error"],
            "authentication_required"
        );

        // rota autenticada qualquer (não só a de sessão) passa pelo mesmo portão
        let (status, _) = http_call(port, "GET", "/control/v1/fs/list?path=.", Some(&desconhecido), None);
        assert_eq!(status, 401, "o portão é único, não rota a rota");
    }

    /// Suíte de auth, parte 2: o ciclo de vida da sessão inteiro na ordem em que um cliente vive —
    /// parear, usar, rotacionar, revogar — e a sessão que expira sozinha. Tudo o que a suíte cria é
    /// revogado no fim: sessão de teste válida sobrevivendo no cofre real seria credencial viva.
    #[test]
    fn a_session_rotates_revokes_and_expires_over_real_http() {
        let _guard = CREDENTIAL_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let port = control_server();
        let client_id = format!("suite-auth-{}", nanoid::nanoid!(8));

        let token = pair_over_http(port, &client_id);

        // 1. a sessão pareada vale e se identifica
        let (status, body) = http_call(port, "GET", "/control/v1/auth/session", Some(&token), None);
        assert_eq!(status, 200, "{body}");
        let payload: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(payload["authenticated"], true);
        assert_eq!(payload["client_id"], client_id.as_str());
        assert!(payload.get("access_token").is_none(), "a sessão não devolve o token de volta");

        // 2. rotacionar troca o token e o antigo deixa de valer na hora (reuso recusado)
        let (status, body) = http_call(port, "POST", "/control/v1/auth/rotate", Some(&token), None);
        assert_eq!(status, 200, "{body}");
        let novo = serde_json::from_str::<Value>(&body).expect("json")["access_token"]
            .as_str()
            .expect("access token")
            .to_string();
        assert_ne!(novo, token, "rotate precisa devolver outro token");
        // O token é aleatório puro (`nanoid!(48)`), sem prefixo de tipo: o que o teste pode fixar é o
        // tamanho e o alfabeto — nada de espaço ou quebra de linha, que quebraria o cabeçalho.
        assert_eq!(novo.len(), 48);
        assert!(
            novo.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "o token precisa ser seguro para o cabeçalho Authorization"
        );
        assert_eq!(
            http_call(port, "GET", "/control/v1/auth/session", Some(&token), None).0,
            401,
            "o token rotacionado não pode continuar valendo"
        );
        assert_eq!(
            http_call(port, "GET", "/control/v1/auth/session", Some(&novo), None).0,
            200
        );

        // 3. revogar mata a sessão, e revogar de novo é recusado (não é operação idempotente)
        let (status, body) = http_call(port, "POST", "/control/v1/auth/revoke", Some(&novo), None);
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json")["revoked"],
            true,
            "revoke precisa confirmar o que fez: {body}"
        );
        assert_eq!(
            http_call(port, "GET", "/control/v1/auth/session", Some(&novo), None).0,
            401
        );
        assert_eq!(
            http_call(port, "POST", "/control/v1/auth/revoke", Some(&novo), None).0,
            401,
            "token já revogado não revoga de novo"
        );

        // 4. sessão expirada: 401 na porta e podada do cofre na mesma passada
        let expirado = pair_over_http(port, &format!("{client_id}-expirado"));
        {
            let mut sessions = state().sessions.lock().expect("lock");
            let entry = sessions
                .iter_mut()
                .find(|session| session.token_hash == token_hash(&expirado))
                .expect("sessão pareada no cofre");
            entry.expires_at = unix_seconds(SystemTime::now() - Duration::from_secs(1));
        }
        assert_eq!(
            http_call(port, "GET", "/control/v1/auth/session", Some(&expirado), None).0,
            401,
            "sessão vencida não autentica"
        );
        assert!(
            !state()
                .sessions
                .lock()
                .expect("lock")
                .iter()
                .any(|session| session.token_hash == token_hash(&expirado)),
            "a sessão vencida tem de sair do cofre na mesma passada"
        );

        // 5. nada desta suíte continua valendo no cofre real
        let restantes = state()
            .sessions
            .lock()
            .expect("lock")
            .iter()
            .filter(|session| session.client_id.starts_with(&client_id))
            .count();
        assert_eq!(restantes, 0, "suíte de auth não pode deixar sessão viva");
    }

    /// Pareia de verdade sobre HTTP: start público, código lido só pela janela, aprovação da janela,
    /// complete devolvendo o Bearer. O token nunca é impresso — o teste só confere forma e prefixo.
    fn pair_over_http(port: u16, client_id: &str) -> String {
        let start = json!({ "client_id": client_id }).to_string();
        let (status, _) = http_request(port, "/control/v1/pairing/start", Some(&start));
        assert_eq!(status, 200, "start do pareamento");
        let body = pairing_body(client_id, &window_code());
        state().pairing_decide(true).expect("janela aprova");
        let (status, payload) = http_request(port, "/control/v1/pairing/complete", Some(&body));
        assert_eq!(status, 200, "complete do pareamento: {payload}");
        let token = serde_json::from_str::<Value>(&payload).expect("json")["access_token"]
            .as_str()
            .expect("access token")
            .to_string();
        assert_eq!(token.len(), 48);
        assert!(
            token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "token fora do alfabeto seguro para cabeçalho"
        );
        token
    }

    /// O evento sai do app e é persistido pelo consumidor: nada de conteúdo livre no payload. Este
    /// teste é o contrato do guarda — a varredura pega a chave em qualquer profundidade, não confunde
    /// `message_bytes` com `message`, e a recusa vale de ponta a ponta no bus real (o evento sujo
    /// não chega em assinante nenhum, o limpo chega).
    #[test]
    fn control_events_refuse_content_bearing_keys() {
        assert_eq!(
            forbidden_event_key(&json!({ "message": "texto do usuário" })).as_deref(),
            Some("message")
        );
        assert_eq!(
            forbidden_event_key(&json!({ "resultado": { "output": "dump de execução" } })).as_deref(),
            Some("output")
        );
        assert_eq!(
            forbidden_event_key(&json!({ "itens": [{ "TEXT": "linha de log" }] })).as_deref(),
            Some("TEXT")
        );
        assert!(forbidden_event_key(
            &json!({ "action": "stage", "repo": "D:\\repo", "message_bytes": 12 })
        )
        .is_none());
        assert!(forbidden_event_key(
            &json!({ "agent_id": "a1", "source": "tui", "status": "started" })
        )
        .is_none());

        let mut receiver = crate::event_bus::subscribe();
        let sujo = format!("test.forbidden.{}", nanoid::nanoid!(8));
        let limpo = format!("test.allowed.{}", nanoid::nanoid!(8));
        emit_control_event(&sujo, None, json!({ "message": "conteúdo não pode sair" }));
        emit_control_event(&limpo, None, json!({ "action": "commit", "repo": "D:\\repo" }));

        let mut vistos: Vec<String> = Vec::new();
        let mut achou_limpo = false;
        for _ in 0..200 {
            match receiver.try_recv() {
                Ok(event) => {
                    achou_limpo |= event.event_type == limpo;
                    vistos.push(event.event_type);
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    if achou_limpo {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
            }
        }
        assert!(
            !vistos.iter().any(|tipo| tipo == &sujo),
            "evento com conteúdo livre saiu no bus: {vistos:?}"
        );
        assert!(achou_limpo, "evento limpo não chegou no bus: {vistos:?}");
    }

    /// Gate do Task 3: `capabilities()` é a promessa feita ao consumidor — a rota do `resume` era
    /// anunciada ali e devolvia 409 fixo, sem existir. Nenhuma rota de `NOT_IMPLEMENTED_ROUTES`
    /// pode aparecer nas duas listas anunciadas.
    #[test]
    fn capabilities_never_announce_an_unimplemented_route() {
        let payload = capabilities();
        let announced: Vec<(&str, &str)> = ["public_endpoints", "authenticated_endpoints"]
            .iter()
            .filter_map(|section| payload.get(*section).and_then(Value::as_array))
            .flatten()
            .map(|entry| {
                (
                    entry.get("method").and_then(Value::as_str).unwrap_or_default(),
                    entry.get("path").and_then(Value::as_str).unwrap_or_default(),
                )
            })
            .collect();
        assert!(!announced.is_empty(), "capabilities sem endpoints anunciados");

        for &(method, path) in NOT_IMPLEMENTED_ROUTES {
            assert!(
                !announced
                    .iter()
                    .any(|(announced_method, announced_path)| *announced_method == method
                        && *announced_path == path),
                "capabilities anunciou {method} {path}, que o control plane não implementa"
            );
        }
    }

    /// A chamada real na rota (servidor e socket reais, como a suíte de pairing) precisa dizer que
    /// não está implementada — nunca devolver o 409 antigo nem um 2xx de mentira.
    #[test]
    fn agent_resume_answers_not_implemented_over_real_http() {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind control server");
        let port = server.server_addr().to_ip().expect("ip listener").port();
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let _ = request.respond(agent_resume_route());
            }
        });

        let (status, body) = http_request(port, "/control/v1/agents/agent-1/resume", None);
        assert_eq!(status, 501);
        assert_eq!(
            serde_json::from_str::<Value>(&body).expect("json body")["error"],
            "agent_resume_not_implemented"
        );

        // o roteador tem de responder por esta função; a asserção fixa a forma do braço de
        // propósito, para um stub inline não voltar (o literal do 409 antigo é quebrado em dois
        // pedaços porque um literal inteiro casaria consigo mesmo)
        let source = include_str!("control.rs");
        assert!(
            source.contains(r#"("POST", Some("resume")) => Some(agent_resume_route())"#),
            "o roteador do resume precisa usar agent_resume_route()"
        );
        let retired_409 = concat!("resume_requires_", "persisted_agent_session");
        assert!(
            !source.contains(retired_409),
            "o 409 do resume anunciado sem implementação não pode voltar"
        );
    }

    /// O anúncio de pane é o que faz a sessão do control plane aparecer na janela. O contrato do
    /// payload é o que este teste fixa: o id do PTY (para o pane se ligar à sessão REAL, sem subir
    /// um segundo processo), o runtime e o diretório — e nada além disso.
    #[test]
    fn the_pane_announcement_carries_the_live_session_id() {
        let payload = pane_open_payload("agent-abc123", "codex", Some("C:\\proj"));
        assert_eq!(payload["pty_id"], "agent-abc123");
        assert_eq!(payload["runtime"], "codex");
        assert_eq!(payload["cwd"], "C:\\proj");
        assert_eq!(
            payload.as_object().expect("objeto json").len(),
            3,
            "canal de UI: só o que abre o pane, sem tarefa nem texto"
        );

        // Sem cwd o payload continua completo: o renderer cai no projeto atual em vez de quebrar.
        assert_eq!(pane_open_payload("x", "shell", None)["cwd"], "");

        // As duas portas de spawn externo anunciam. Um spawn sem anúncio é exatamente o defeito
        // que este canal corrige (o processo vivo no /terminals e nenhum pane na tela). Os
        // literais vão quebrados de propósito: um literal inteiro casaria consigo mesmo aqui.
        let source = include_str!("control.rs");
        let spawn_call = concat!("announce_pane_open(app, &id, &agent, ", "cwd.as_deref());");
        assert_eq!(
            source.matches(spawn_call).count(),
            1,
            "agent_spawn anuncia a sessão que subiu"
        );
        let terminal_call = concat!("announce_pane_open(&app, id, &runtime, ", "cwd.as_deref());");
        assert_eq!(
            source.matches(terminal_call).count(),
            1,
            "POST /terminals anuncia a sessão que subiu"
        );
    }
}

#[cfg(test)]
mod proof_tail_tests {
    use super::strip_terminal_escapes;

    /// O rastro do registro tem que ser legível: a saída crua de uma TUI é feita de CSI/OSC, e sem
    /// limpar sobra lixo que ninguém lê. O caso real é o do claude (título OSC + cores + repetição
    /// de linha na repintura da TUI).
    #[test]
    fn the_proof_trace_drops_terminal_sequences_and_repeats() {
        let raw = "\u{1b}]0;claude\u{7}\u{1b}[?9001h\u{1b}[2J\u{1b}[1;2HAccessing workspace:\r\n\
                   \u{1b}[38;2;150;108;30mQuick safety check\u{1b}[m\r\n\
                   Quick safety check\r\n\
                   \u{1b}[?25l❯ 1. Yes, I trust this folder\u{1b}[?25h\r\n";

        let lines = strip_terminal_escapes(raw);
        assert_eq!(
            lines,
            vec![
                "Accessing workspace:",
                "Quick safety check",
                "❯ 1. Yes, I trust this folder",
            ],
            "sem sequência de terminal, sem linha repetida na repintura"
        );
        assert!(!lines.iter().any(|line| line.contains('\u{1b}')), "sobrou ESC: {lines:?}");
        assert!(!lines.iter().any(|line| line.contains("9001h")), "sobrou CSI: {lines:?}");
    }

    /// OSC terminada por `ESC \` (ST) também sai inteira — é o que o Windows Terminal manda.
    #[test]
    fn the_proof_trace_handles_st_terminated_osc() {
        let lines = strip_terminal_escapes("antes\u{1b}]0;titulo\u{1b}\\depois");
        assert_eq!(lines, vec!["antesdepois"]);
    }
}
