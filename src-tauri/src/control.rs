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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

/// Ponte event bus → SSE. O bus é a fonte única do ciclo de vida (scheduler, supervisor, rotas do
/// control plane, pty) e o `/control/v1/events` é o consumidor externo; sem a ponte o stream nasce
/// quase vazio, que era o defeito desta task. Idempotente: a primeira assinatura liga.
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
                Ok(payload) => publish_event(&payload.event_type, &bus_envelope(&payload)),
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
fn emit_control_event(event_type: &str, agent_id: Option<String>, payload: Value) {
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

fn agents() -> Value {
    let entries = [
        ("shell", "pwsh.exe", true),
        ("codex", "codex", true),
        ("claude", "claude", true),
        ("opencode", "opencode", true),
        ("antigravity", "antigravity", false),
        ("cursor", "cursor", false),
        ("copilot", "github-copilot", false),
        ("mimo", "mimo", false),
        ("freebuff", "freebuff", false),
    ];
    json!({ "agents": entries.into_iter().map(|(id, command, supported)| probe_agent(id, command, supported)).collect::<Vec<_>>() })
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

fn agent_spawn(app: &AppHandle, input: AgentSpawnInput) -> Result<Value, String> {
    let agent = input.agent.trim().to_lowercase();
    if !matches!(agent.as_str(), "shell" | "claude" | "codex" | "opencode") {
        return Err(format!("agent_runtime_not_supported:{agent}"));
    }
    let id = valid_runtime_id(&input.id.unwrap_or_else(|| format!("agent-{}", nanoid::nanoid!(12))))?;
    let terminal = terminal_start(app, TerminalStartInput {
        cols: input.cols,
        rows: input.rows,
        id: Some(id.clone()),
        command: Some(agent.clone()),
        cwd: input.cwd,
        extra_args: input.extra_args,
        launcher_override: input.launcher_override,
        env: input.env,
    })?;
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

fn agent_route(app: &AppHandle, method: &str, path: &str, url: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if method == "POST" && path == "/control/v1/agents/spawn" {
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
            terminal_write(app, id.clone(), message)?;
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
        ("PUT", "/control/v1/fs/write") => Some(match read_json::<FilesystemWriteInput>(request).and_then(|input| {
            let path = std::path::PathBuf::from(input.path.trim());
            if path.as_os_str().is_empty() {
                return Err("path_required".to_string());
            }
            if !path.parent().is_some_and(|parent| parent.is_dir()) {
                return Err("parent_directory_not_found".to_string());
            }
            std::fs::write(path, input.content).map_err(|error| error.to_string())
        }) {
            Ok(()) => json_response(200, json!({ "written": true })),
            Err(error) => error_response(400, &error),
        }),
        ("POST", "/control/v1/fs/mkdir") => Some(match read_json::<FilesystemPathInput>(request).and_then(|input| std::fs::create_dir_all(input.path).map_err(|error| error.to_string())) {
            Ok(()) => json_response(201, json!({ "created": true })),
            Err(error) => error_response(400, &error),
        }),
        ("POST", "/control/v1/fs/move") => Some(match read_json::<FilesystemMoveInput>(request).and_then(|input| std::fs::rename(input.path, input.destination).map_err(|error| error.to_string())) {
            Ok(()) => json_response(200, json!({ "moved": true })),
            Err(error) => error_response(400, &error),
        }),
        ("DELETE", "/control/v1/fs") => Some(match read_json::<FilesystemPathInput>(request).or_else(|_| query_parameter(url, "path").map(|path| FilesystemPathInput { path }).ok_or_else(|| "path_required".to_string())).and_then(|input| crate::filesystem::delete_filesystem_entry(input.path)) {
            Ok(()) => json_response(200, json!({ "deleted": true })),
            Err(error) => error_response(400, &error),
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
            "/control/v1/git/init" => Some(match read_json::<GitInitInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_init(input.path))) {
                Ok(repo_root) => json_response(201, json!({ "repo_root": repo_root })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/stage" => Some(match read_json::<GitPathsInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_stage(input.repo_root, input.paths))) {
                Ok(()) => json_response(200, json!({ "staged": true })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/unstage" => Some(match read_json::<GitPathsInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_unstage(input.repo_root, input.paths))) {
                Ok(()) => json_response(200, json!({ "unstaged": true })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/discard" => Some(match read_json::<GitDiscardInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_discard(input.repo_root, input.paths, input.untracked))) {
                Ok(()) => json_response(200, json!({ "discarded": true })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/commit" => Some(match read_json::<GitCommitInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_commit(input.repo_root, input.message))) {
                Ok(output) => json_response(200, json!({ "committed": true, "output": output })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/pull" => Some(match read_json::<GitInitInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_pull(input.path))) {
                Ok(output) => json_response(200, json!({ "pulled": true, "output": output })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/push" => Some(match read_json::<GitInitInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_push(input.path))) {
                Ok(output) => json_response(200, json!({ "pushed": true, "output": output })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/branch" => Some(match read_json::<GitBranchInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_create_branch_from_commit(input.repo, input.hash, input.branch_name))) {
                Ok(()) => json_response(201, json!({ "created": true })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/cherry-pick" => Some(match read_json::<GitHashInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_cherry_pick_commit(input.repo, input.hash))) {
                Ok(output) => json_response(200, json!({ "cherry_picked": true, "output": output })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/revert" => Some(match read_json::<GitHashInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_revert_commit(input.repo, input.hash))) {
                Ok(output) => json_response(200, json!({ "reverted": true, "output": output })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/git/reset" => Some(match read_json::<GitResetInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::git_control::git_reset_to_commit(input.repo, input.hash, input.mode))) {
                Ok(()) => json_response(200, json!({ "reset": true })),
                Err(error) => error_response(400, &error),
            }),
            "/control/v1/worktrees" => Some(match read_json::<WorktreeProvisionInput>(request).and_then(|input| tauri::async_runtime::block_on(crate::worktrees::worktree_provision(input.repo, input.agent_id, input.mode))) {
                Ok(worktree) => json_response(201, json!({ "worktree": worktree })),
                Err(error) => error_response(400, &error),
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
        return Some(match tauri::async_runtime::block_on(crate::worktrees::worktree_remove(repo, agent_id.to_string(), force)) {
            Ok(()) => json_response(200, json!({ "deleted": true })),
            Err(error) => error_response(400, &error),
        });
    }
    None
}

fn validation_route(method: &str, path: &str, request: &mut Request) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if method != "POST" || path != "/control/v1/validation/run" {
        return None;
    }
    Some(match read_json::<ValidationInput>(request).and_then(|input| crate::validation::run_validation(input.cwd, input.commands)) {
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
        json_response(200, agents())
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
        match read_json::<TerminalStartInput>(&mut request).and_then(|input| terminal_start(&app, input)) {
            Ok(payload) => json_response(201, payload),
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
    } else if path == "/control/v1/auth/session" && method == "GET" {
        match state().authenticate(token) {
            Ok(session) => json_response(200, json!({ "authenticated": true, "client_id": session.client_id, "created_at": session.created_at, "expires_at": session.expires_at })),
            Err(_) => unauthorized_response(),
        }
    } else if path == "/control/v1/auth/rotate" && method == "POST" {
        match state().rotate(token) {
            Ok(payload) => json_response(200, payload),
            Err(_) => unauthorized_response(),
        }
    } else if path == "/control/v1/auth/revoke" && method == "POST" {
        match state().revoke(token) {
            Ok(payload) => json_response(200, payload),
            Err(_) => unauthorized_response(),
        }
    } else if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
        error_response(405, "method_not_allowed")
    } else {
        error_response(404, "control_route_not_found")
    };
    let _ = request.respond(response);
    true
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

    fn http_request(port: u16, path: &str, body: Option<&str>) -> (u16, String) {
        let body_text = body.unwrap_or("");
        let raw_request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_text}",
            body_text.len()
        );
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to control server");
        stream.write_all(raw_request.as_bytes()).expect("write request");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).expect("read response");
        let status = raw
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("status code");
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.trim().to_string())
            .unwrap_or_default();
        (status, body)
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

    /// Acumula do stream até todos os `needles` aparecerem ou o deadline estourar. Dois frames
    /// podem chegar no mesmo recv, então a asserção de ordem é feita no buffer acumulado.
    fn sse_read_until_all(
        stream: &mut std::net::TcpStream,
        needles: &[&str],
        deadline: std::time::Instant,
    ) -> String {
        let mut buffer = String::new();
        let mut chunk = [0u8; 4096];
        while std::time::Instant::now() < deadline
            && needles.iter().any(|needle| !buffer.contains(needle))
        {
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

        // nomes exclusivos deste teste: o processo inteiro compartilha o mesmo bus, e os testes
        // rodam em paralelo
        emit_control_event("sse.bridge.first", None, json!({ "marker": "um" }));
        crate::event_bus::publish_event_simple(
            "sse.bridge.second",
            "sched-test",
            None,
            Some("agent-1".to_string()),
            json!({ "marker": "dois" }),
        );

        let frames = sse_read_until_all(
            &mut stream,
            &["event: sse.bridge.first", "event: sse.bridge.second"],
            deadline,
        );
        let first_at = frames
            .find("event: sse.bridge.first")
            .unwrap_or_else(|| panic!("primeiro evento não chegou no SSE: {frames}"));
        let second_at = frames
            .find("event: sse.bridge.second")
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
            frames.contains("\"marker\":\"um\"") && frames.contains("\"marker\":\"dois\""),
            "o data do bus precisa chegar inteiro: {frames}"
        );
        assert!(
            frames.contains("\"agent_id\":\"agent-1\""),
            "o envelope do bus precisa manter agent_id: {frames}"
        );

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
}
