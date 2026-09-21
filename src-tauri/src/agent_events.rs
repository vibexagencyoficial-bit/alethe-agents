// Listener da POC do canvas de subagents (Fase 1).
//
// O Claude Code dispara hooks `SubagentStart`/`SubagentStop` como POST HTTP

use std::io::Read;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

const HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 9123;
const MAX_PORT: u16 = 9143;
const BODY_LIMIT: u64 = 1024 * 1024; // 1 MB
static LISTENER_PORT: AtomicU16 = AtomicU16::new(0);
static LISTENER_TOKEN: OnceLock<String> = OnceLock::new();

fn init_token() -> &'static str {
    LISTENER_TOKEN.get_or_init(|| nanoid::nanoid!(32))
}

fn check_token(request: &tiny_http::Request) -> bool {
    let expected = init_token();
    request
        .headers()
        .iter()
        .any(|h| h.field.as_str() == "X-Alethe-Token" && h.value.as_str() == expected)
}

fn listener_addr(port: u16) -> String {
    format!("{HOST}:{port}")
}

fn listener_endpoint(port: u16) -> String {
    format!("http://{HOST}:{port}")
}

fn current_listener_port() -> Option<u16> {
    let port = LISTENER_PORT.load(Ordering::SeqCst);
    (port != 0).then_some(port)
}

fn wait_for_listener_port() -> Option<u16> {
    let start = Instant::now();
    loop {
        if let Some(port) = current_listener_port() {
            return Some(port);
        }
        if start.elapsed() >= Duration::from_secs(2) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tauri::command]
pub fn agent_hooks_endpoint() -> Result<String, String> {
    let port = wait_for_listener_port()
        .ok_or_else(|| "listener de agents ainda nao esta disponivel".to_string())?;
    Ok(listener_endpoint(port))
}

#[tauri::command]
pub fn agent_hooks_token() -> String {
    init_token().to_string()
}

#[tauri::command]
pub fn agent_hooks_settings_path() -> Result<String, String> {
    let port = wait_for_listener_port()
        .ok_or_else(|| "listener de agents ainda nao esta disponivel".to_string())?;
    let endpoint = listener_endpoint(port);
    // Namespaced by port so a second instance cannot overwrite the first one's endpoint and
    // silently redirect its agents.
    let path = std::env::temp_dir().join(format!("alethe-agent-hooks-{port}.json"));
    let token = init_token();
    let hook = serde_json::json!([
        { "hooks": [ {
            "type": "http",
            "url": format!("{endpoint}/hook"),
            "timeout": 5,
            "headers": { "X-Alethe-Token": token }
        } ] }
    ]);
    let settings = serde_json::json!({


        "teammateMode": "in-process",
        "hooks": {
            "SubagentStart": hook.clone(),
            "SubagentStop": hook.clone(),
            // Fase 2: tool calls em tempo real. PreToolUse dentro de subagent

            "PreToolUse": hook.clone(),
            "PostToolUse": hook.clone(),


            "TeammateIdle": hook.clone(),
            "TaskCreated": hook.clone(),
            "TaskCompleted": hook
        }
    });
    let body = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    eprintln!(
        "[agent_events] hooks settings escrito em {}",
        path.display()
    );
    Ok(path.to_string_lossy().to_string())
}

pub fn start_listener(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_error: Option<String> = None;
        let mut bound: Option<(tiny_http::Server, u16)> = None;

        for port in DEFAULT_PORT..=MAX_PORT {
            let addr = listener_addr(port);
            match tiny_http::Server::http(&addr) {
                Ok(server) => {
                    bound = Some((server, port));
                    break;
                }
                Err(e) => {
                    last_error = Some(format!("{addr}: {e}"));
                }
            }
        }

        let Some((server, port)) = bound else {
            eprintln!(
                "[agent_events] falha ao subir listener em {HOST}:{DEFAULT_PORT}-{MAX_PORT}: {}",
                last_error.unwrap_or_else(|| "sem erro detalhado".to_string())
            );
            return;
        };

        LISTENER_PORT.store(port, Ordering::SeqCst);
        eprintln!("[agent_events] ouvindo em {}", listener_addr(port));

        let pool = std::sync::Arc::new(crate::request_pool::RequestPool::new(
            crate::request_pool::DEFAULT_REQUEST_LIMIT,
        ));
        let dispatch_app = app.clone();
        accept_loop(server, pool, move |request, url| {
            dispatch_request(dispatch_app.clone(), request, &url, port);
        });
    });
}

/// Laço de accept com um pedido por thread, limitado pelo `RequestPool`.
///
/// Antes desta função o handler rodava inline aqui e um pedido lento — os caminhos de git e
/// do gateway usam `block_on` — segurava o aceite da conexão seguinte, o que derrubava a
/// latência do `/control/v1/health` de todo mundo (Task 2 do plano
/// `alethe-circuito-completo`).
///
/// O `tiny_http::Request` é `Send` de propósito e o próprio tiny_http reordena as respostas
/// de uma mesma conexão, então o paralelismo não muda a ordem que o cliente enxerga.
fn accept_loop<D>(
    server: tiny_http::Server,
    pool: std::sync::Arc<crate::request_pool::RequestPool>,
    dispatch: D,
) where
    D: Fn(tiny_http::Request, String) + Send + Sync + 'static,
{
    let dispatch = std::sync::Arc::new(dispatch);

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        let Some(permit) = pool.acquire() else {
            eprintln!("[agent_events] listener saturado: {url} respondeu 503");
            let _ = request.respond(saturated_response());
            continue;
        };

        let dispatch = std::sync::Arc::clone(&dispatch);
        let thread_url = url.clone();
        let spawned = std::thread::Builder::new()
            .name("alethe-request".to_string())
            .spawn(move || {
                // A vaga vive enquanto o pedido viver e volta no Drop, mesmo com panico.
                let _permit = permit;
                dispatch(request, thread_url);
            });
        if let Err(error) = spawned {
            // Sem thread não há resposta: o tiny_http devolve 500 sozinho quando o `Request`
            // é dropado, e a vaga volta junto com a closure.
            eprintln!("[agent_events] falha ao subir a thread de {url}: {error}");
        }
    }
}

/// Recusa explícita quando o pool está cheio: melhor o cliente ouvir "volte depois" agora do
/// que todos esperarem atrás de um pedido lento.
fn saturated_response() -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_string("{\"error\":\"listener_saturated\"}")
        .with_status_code(503)
        .with_header(
            tiny_http::Header::from_bytes("Content-Type", "application/json").expect("static"),
        )
        .with_header(tiny_http::Header::from_bytes("Retry-After", "1").expect("static"))
}

/// Atende um pedido já autorizado a rodar numa thread própria. Antes da Task 2 este corpo era
/// o corpo do laço de accept; a única mudança foi trocar `continue` por `return`.
fn dispatch_request(app: AppHandle, mut request: tiny_http::Request, url: &str, port: u16) {
    // O Control Plane possui autenticação própria e precisa ler o body no
    // módulo de contrato. Ele é despachado antes do token legado X-Alethe-Token.
    if crate::control::is_control_path(url) {
        crate::control::handle_request(app.clone(), request, url, port);
        return;
    }

    if !check_token(&request) {
        let _ = request.respond(tiny_http::Response::empty(401));
        return;
    }

    let mut body = String::new();
    if let Err(e) = request
        .as_reader()
        .take(BODY_LIMIT)
        .read_to_string(&mut body)
    {
        eprintln!("[agent_events] erro lendo corpo: {e}");
        let _ = request.respond(tiny_http::Response::empty(400));
        return;
    }

    // processo real (claude/codex/opencode) via
    // `curl -X POST /spawn -d '{"agent":"codex","task":"...","mode":"exec"}'`.
    // O Alethe emite `agent-spawn`; o front sobe um PTY worker. Campos:

    if url.starts_with("/mcp") {
        let app = app.clone();
        std::thread::spawn(move || {
            let state = app.state::<crate::orchestrator::OrchestratorState>();
            match crate::orchestrator::handle_mcp_body(Some(&app), &state, &body) {
                Some(payload) => {
                    let header =
                        tiny_http::Header::from_bytes("Content-Type", "application/json")
                            .expect("static header");
                    let _ =
                        request.respond(tiny_http::Response::from_string(payload).with_header(header));
                }
                None => {
                    let _ = request.respond(tiny_http::Response::empty(202));
                }
            }
        });
        return;
    }

    if url.starts_with("/spawn") {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(payload) => {
                let agent = payload
                    .get("agent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !matches!(agent.as_str(), "shell" | "claude" | "codex" | "opencode") {
                    let _ = request.respond(
                        tiny_http::Response::from_string(
                            "agent invalido (use claude|codex|opencode)",
                        )
                        .with_status_code(400),
                    );
                    return;
                }
                let job_id = payload
                    .get("job_id")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("sandbox-job-{}", nanoid::nanoid!(10)));
                let mut event_payload = payload;
                if let Some(object) = event_payload.as_object_mut() {
                    object.insert(
                        "job_id".to_string(),
                        serde_json::Value::String(job_id.clone()),
                    );
                }
                eprintln!("[agent_events] /spawn agent={agent} job_id={job_id}");
                let _ = app.emit("agent-spawn", &event_payload);
                let response = serde_json::json!({
                    "accepted": true,
                    "job_id": job_id,
                    "agent": agent,
                    "status": "queued"
                });
                let _ = request.respond(
                    tiny_http::Response::from_string(response.to_string()).with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json")
                            .unwrap(),
                    ),
                );
            }
            Err(e) => {
                let _ = request.respond(
                    tiny_http::Response::from_string(format!("/spawn espera JSON: {e}"))
                        .with_status_code(400),
                );
            }
        }
        return;
    }

    // Alias legado: o control plane antigo despacha texto cru pro codex

    // emitindo agent-spawn com agent=codex.
    if url.starts_with("/codex") {
        let task = body.trim().to_string();
        eprintln!("[agent_events] /codex (legado) task ({} chars)", task.len());
        let payload = serde_json::json!({ "agent": "codex", "task": task });
        let _ = app.emit("agent-spawn", &payload);
        let _ = request.respond(tiny_http::Response::from_string(
            "queued no terminal codex do Alethe",
        ));
        return;
    }

    // Bridge do plugin OpenCode (opencode_bridge.rs) — reporta
    // working/idle real de sessoes OpenCode. Campos: directory

    // state ("working" | "idle").
    if url.starts_with("/opencode-status") {
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(payload) => {
                let _ = app.emit("opencode-bridge-status", &payload);
            }
            Err(e) => eprintln!("[agent_events] /opencode-status payload inválido: {e}"),
        }
        let _ = request.respond(tiny_http::Response::empty(200));
        return;
    }

    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(payload) => {
            let get = |k: &str| {
                payload
                    .get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_owned()
            };
            eprintln!(
                "[agent_events] {} agent_id={} agent_type={}",
                get("hook_event_name"),
                get("agent_id"),
                get("agent_type"),
            );

            let preview: String = body.chars().take(600).collect();
            eprintln!("[agent_events] payload: {preview}");
            if let Err(e) = app.emit("agent-hook", &payload) {
                eprintln!("[agent_events] falha ao emitir agent-hook: {e}");
            }
        }
        Err(e) => eprintln!("[agent_events] POST não-JSON ignorado: {e}"),
    }

    let _ = request.respond(tiny_http::Response::empty(200));
}

#[cfg(test)]
mod concurrency_tests {
    // Testes de uso do laço de accept (Task 2 do plano alethe-circuito-completo): servidor
    // tiny_http real em 127.0.0.1:0 e clientes HTTP de verdade em cima de `TcpStream`. O que
    // está sob teste é o laço — limite do pool, thread por pedido, 503 na saturação e ordem
    // por conexão; o handler injetado troca só o que depende do `AppHandle`.
    //
    // O laço fica rodando depois do teste: cada cenário usa uma porta efêmera própria e o
    // processo da suíte morre no fim, então não há o que desmontar.
    use super::*;
    use crate::request_pool::RequestPool;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    /// No app real quem demora assim são os caminhos de git/gateway com `block_on`.
    const SLOW_REQUEST_MS: u64 = 1500;
    const HEALTH_CLIENTS: usize = 100;
    const HEALTH_P95_BUDGET_MS: f64 = 500.0;

    fn bind_listener() -> (tiny_http::Server, u16) {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind em 127.0.0.1:0");
        let port = server
            .server_addr()
            .to_ip()
            .expect("endereço de loopback")
            .port();
        (server, port)
    }

    /// `/control/v1/health` responde o payload real do control plane; o pedido lento fica com
    /// a thread parada por `slow_ms` antes de responder.
    fn test_dispatch(
        port: u16,
        slow_ms: u64,
        slow_started: Arc<AtomicUsize>,
    ) -> impl Fn(tiny_http::Request, String) + Send + Sync + 'static {
        move |mut request, url| {
            let (status, body) = if url.starts_with("/control/v1/health") {
                (200, crate::control::health(port).to_string())
            } else if url.starts_with("/control/v1/validation/run") {
                slow_started.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(slow_ms));
                (200, "{\"validation\":{\"slow\":true}}".to_string())
            } else {
                (404, "{\"error\":\"control_route_not_found\"}".to_string())
            };
            let _ =
                request.respond(tiny_http::Response::from_string(body).with_status_code(status));
        }
    }

    /// O laço exatamente como era antes da Task 2: handler inline, sem pool e sem thread.
    fn serial_accept_loop<D>(server: tiny_http::Server, dispatch: D)
    where
        D: Fn(tiny_http::Request, String),
    {
        for request in server.incoming_requests() {
            let url = request.url().to_string();
            dispatch(request, url);
        }
    }

    fn spawn_slow_request(port: u16) -> std::thread::JoinHandle<(u16, f64)> {
        std::thread::spawn(move || timed_get(port, "/control/v1/validation/run"))
    }

    fn wait_until_slow_is_in_flight(slow_started: &Arc<AtomicUsize>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while slow_started.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "o pedido lento não chegou ao handler em 5s"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_until_listener_ready(port: u16) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (status, _, _) = timed_get_raw(port, "/control/v1/health");
            if status == 200 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "listener não subiu em 127.0.0.1:{port}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn timed_get(port: u16, path: &str) -> (u16, f64) {
        let (status, elapsed, _) = timed_get_raw(port, path);
        (status, elapsed)
    }

    /// `Connection: close` de propósito: o servidor fecha no fim da resposta e a leitura vai
    /// até o fim do corpo sem depender de tempo.
    fn timed_get_raw(port: u16, path: &str) -> (u16, f64, String) {
        let start = Instant::now();
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("conectar em 127.0.0.1");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout de leitura");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .expect("escrever o pedido");
        stream.flush().expect("flush do pedido");
        let raw = read_all(&mut stream);
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        (status_of(&raw), elapsed, raw)
    }

    fn read_all(stream: &mut TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => raw.extend_from_slice(&buffer[..read]),
                Err(error) => panic!("leitura do socket falhou: {error}"),
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    /// Duas requisições na mesma conexão keep-alive, sem `Connection: close`: lê até juntar
    /// `expected` respostas e depois dá um tempo curto para o corpo da última chegar.
    fn read_responses(stream: &mut TcpStream, expected: usize) -> String {
        let mut raw = String::new();
        let mut buffer = [0u8; 4096];
        while raw.matches("HTTP/1.1 ").count() < expected {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => raw.push_str(&String::from_utf8_lossy(&buffer[..read])),
                Err(error) => panic!("leitura do socket falhou: {error}"),
            }
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout curto");
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }
            raw.push_str(&String::from_utf8_lossy(&buffer[..read]));
        }
        raw
    }

    fn status_of(raw: &str) -> u16 {
        raw.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    /// `clients` clientes concorrentes em `/control/v1/health`, cada um na própria conexão.
    fn hammer_health(port: u16, clients: usize) -> (Vec<f64>, usize) {
        let samples = Arc::new(Mutex::new(Vec::new()));
        let failures = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..clients {
            let samples = Arc::clone(&samples);
            let failures = Arc::clone(&failures);
            handles.push(std::thread::spawn(move || {
                let (status, elapsed) = timed_get(port, "/control/v1/health");
                if status == 200 {
                    samples.lock().expect("lock das amostras").push(elapsed);
                } else {
                    failures.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("join do cliente");
        }
        let failures = failures.load(Ordering::SeqCst);
        let samples = samples.lock().expect("lock das amostras").clone();
        (samples, failures)
    }

    fn percentile(samples: &mut [f64], percent: f64) -> f64 {
        assert!(!samples.is_empty(), "sem amostras para o percentil");
        samples.sort_by(|a, b| a.partial_cmp(b).expect("sem NaN"));
        let rank = ((percent / 100.0) * samples.len() as f64).ceil() as usize;
        samples[rank.saturating_sub(1).min(samples.len() - 1)]
    }

    #[test]
    fn health_stays_responsive_during_a_slow_request_and_the_serial_loop_does_not() {
        // 1) "antes": o laço inline medido no mesmo run, para o teste carregar a prova de que
        //    ele reprova no orçamento — se alguém voltar a serializar, isto quebra aqui.
        let (serial_server, serial_port) = bind_listener();
        let serial_slow = Arc::new(AtomicUsize::new(0));
        let serial_dispatch =
            test_dispatch(serial_port, SLOW_REQUEST_MS, Arc::clone(&serial_slow));
        std::thread::spawn(move || serial_accept_loop(serial_server, serial_dispatch));

        let serial_slow_request = spawn_slow_request(serial_port);
        wait_until_slow_is_in_flight(&serial_slow);
        let (mut serial_samples, serial_failures) = hammer_health(serial_port, HEALTH_CLIENTS);
        let serial_p95 = percentile(&mut serial_samples, 95.0);
        let (serial_status, _) = serial_slow_request.join().expect("pedido lento (antes)");
        assert_eq!(serial_status, 200, "o pedido lento termina no fim");
        assert_eq!(serial_failures, 0, "o laço serial não recusa ninguém");
        assert!(
            serial_p95 >= SLOW_REQUEST_MS as f64 * 0.9,
            "o laço serial deveria prender o /health atrás do pedido lento, p95 {serial_p95:.0}ms"
        );

        // 2) "depois": o mesmo cenário no laço com pool.
        let (pooled_server, pooled_port) = bind_listener();
        let pooled_slow = Arc::new(AtomicUsize::new(0));
        let pooled_dispatch =
            test_dispatch(pooled_port, SLOW_REQUEST_MS, Arc::clone(&pooled_slow));
        let pool = Arc::new(RequestPool::new(crate::request_pool::DEFAULT_REQUEST_LIMIT));
        let loop_pool = Arc::clone(&pool);
        std::thread::spawn(move || accept_loop(pooled_server, loop_pool, pooled_dispatch));

        let pooled_slow_request = spawn_slow_request(pooled_port);
        wait_until_slow_is_in_flight(&pooled_slow);
        let (mut pooled_samples, pooled_failures) = hammer_health(pooled_port, HEALTH_CLIENTS);
        let pooled_p95 = percentile(&mut pooled_samples, 95.0);
        let (pooled_status, pooled_slow_elapsed) =
            pooled_slow_request.join().expect("pedido lento (depois)");

        assert_eq!(pooled_status, 200, "o pedido lento continua respondendo");
        assert!(
            pooled_slow_elapsed >= SLOW_REQUEST_MS as f64,
            "o cenário só vale se o pedido lento realmente demorar: {pooled_slow_elapsed:.0}ms"
        );
        assert_eq!(
            pooled_samples.len(),
            HEALTH_CLIENTS,
            "todos os {HEALTH_CLIENTS} clientes precisam ser atendidos"
        );
        assert_eq!(
            pooled_failures, 0,
            "uma vaga ocupada deixa {DEFAULT_REQUEST_LIMIT} - 1 livres para o /health",
            DEFAULT_REQUEST_LIMIT = crate::request_pool::DEFAULT_REQUEST_LIMIT
        );
        assert!(
            pooled_p95 < HEALTH_P95_BUDGET_MS,
            "p95 do /health com pedido lento em andamento: {pooled_p95:.0}ms (orçamento {HEALTH_P95_BUDGET_MS}ms)"
        );

        println!(
            "[task2] p95 de {HEALTH_CLIENTS} GET /health com um pedido lento de {SLOW_REQUEST_MS}ms: \
             serial={serial_p95:.0}ms | pool={pooled_p95:.0}ms | recusas serial={serial_failures} pool={pooled_failures}"
        );
    }

    #[test]
    fn a_saturated_listener_answers_503_instead_of_queueing() {
        let (server, port) = bind_listener();
        let slow_started = Arc::new(AtomicUsize::new(0));
        let dispatch = test_dispatch(port, 600, Arc::clone(&slow_started));
        let pool = Arc::new(RequestPool::with_wait(1, Duration::from_millis(80)));
        let loop_pool = Arc::clone(&pool);
        std::thread::spawn(move || accept_loop(server, loop_pool, dispatch));

        let slow_request = spawn_slow_request(port);
        wait_until_slow_is_in_flight(&slow_started);

        let (status, elapsed, raw) = timed_get_raw(port, "/control/v1/health");
        assert_eq!(status, 503, "a vaga única está com o pedido lento: {raw}");
        assert!(
            raw.contains("listener_saturated") && raw.contains("Retry-After: 1"),
            "o 503 diz o motivo e quando voltar: {raw}"
        );
        assert!(
            elapsed < 400.0,
            "o 503 precisa sair na hora, não depois do pedido lento: {elapsed:.0}ms"
        );

        let (slow_status, _) = slow_request.join().expect("pedido lento");
        assert_eq!(slow_status, 200, "quem estava na vaga termina normalmente");
        assert_eq!(pool.active(), 0, "a vaga volta depois do pedido");
    }

    #[test]
    fn a_single_connection_keeps_response_order_with_a_slow_and_a_fast_request() {
        let (server, port) = bind_listener();
        let slow_started = Arc::new(AtomicUsize::new(0));
        let dispatch = test_dispatch(port, 400, Arc::clone(&slow_started));
        let pool = Arc::new(RequestPool::new(crate::request_pool::DEFAULT_REQUEST_LIMIT));
        let loop_pool = Arc::clone(&pool);
        std::thread::spawn(move || accept_loop(server, loop_pool, dispatch));
        wait_until_listener_ready(port);

        // Duas requisições na mesma conexão, sem esperar a resposta da primeira: o tiny_http
        // entrega as duas na hora e as reordena na saída. O pool não pode furar essa ordem.
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("conectar");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout de leitura");
        write!(
            stream,
            "GET /control/v1/validation/run HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n\
             GET /control/v1/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .expect("escrever os dois pedidos");
        stream.flush().expect("flush");
        let raw = read_responses(&mut stream, 2);

        let responses: Vec<&str> = raw.split("HTTP/1.1 ").skip(1).collect();
        assert_eq!(
            responses.len(),
            2,
            "duas respostas na mesma conexão, nesta ordem: {raw}"
        );
        assert!(
            responses[0].contains("validation"),
            "a primeira resposta é a do pedido lento: {}",
            responses[0]
        );
        assert!(
            responses[1].contains("alethe-control"),
            "a segunda é a do /health, que terminou antes e mesmo assim esperou a vez: {}",
            responses[1]
        );
    }
}
