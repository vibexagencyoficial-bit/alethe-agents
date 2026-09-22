//! Registry de runtimes: a fonte única de "o que existe", "o que está instalado" e "o que tem
//! efeito comprovado".
//!
//! Antes deste módulo, o control plane tinha duas listas hardcoded: a allowlist de `agent_spawn`
//! (`shell`/`claude`/`codex`/`opencode`) e o `execution_supported` de `/agents`. As duas diziam a
//! mesma coisa sem medir nada — `antigravity`, instalado na máquina, era recusado no spawn, e um
//! runtime cujo CLI não funciona aparecia como executável só porque estava na lista.
//!
//! Aqui `execution_supported` não é opinião: é o registro de uma prova com efeito no disco. O
//! contrato da prova é o do plano: o runtime **cria** `proof-<id>.txt` com `<ID>_OK` e, sob
//! **steer**, **altera** o mesmo arquivo para `<ID>_STEER_OK`. Quem lê o arquivo é o app (rota de
//! prova), não o chamador: o registro não é a palavra de quem pediu, é a medição de quem verifica.
//! Sem prova, o spawn pelo control plane é recusado com motivo — o CLI pode estar instalado e mesmo
//! assim não ter efeito comprovado.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tauri::AppHandle;

/// Como a prova é dirigida neste runtime. O contrato medido é sempre o mesmo — o arquivo com o
/// conteúdo exato —, mas o que vai para o PTY muda: um CLI de agente entende um pedido em prosa
/// (quem escreve o arquivo é o modelo dele), e o shell não tem modelo nenhum para interpretar
/// prosa, então recebe o próprio comando. Sem isso, provar o shell seria pedir ao pwsh que
/// executasse uma frase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofDriver {
    /// CLI de agente (tem LLM): o pedido é uma frase em português.
    AgentPrompt,
    /// Shell: o pedido é o comando literal, porque não há modelo para interpretar prosa.
    ShellCommand,
}

/// Um runtime conhecido pelo control plane. `unrestricted_args` é o perfil que o app usa no "Modo
/// irrestrito" deste runtime — espelho de `UNRESTRICTED_FLAG` em `src/lib/types.ts`, que o humano
/// liga no terminal. A prova usa este perfil porque um agente dirigido pelo control plane roda sem
/// humano para aprovar cada escrita, e o registro guarda os args usados: o registry NÃO aplica
/// bypass sozinho (quem chama passa `extra_args` explícito, e a prova mostra com quais).
pub struct RuntimeSpec {
    pub id: &'static str,
    pub command: &'static str,
    pub unrestricted_args: &'static [&'static str],
    pub proof_driver: ProofDriver,
    /// Handshake de boot: o que o runtime recebe antes do primeiro pedido. Um `""` é um Enter puro,
    /// que aceita a opção padrão destacada — o que um humano faz para fechar o diálogo de primeira
    /// execução ("confia nesta pasta?") que os CLIs de agente abrem sozinhos. Vazio = o runtime não
    /// tem diálogo (o shell, por exemplo).
    pub boot_inputs: &'static [&'static str],
}

const ENTER: &[&str] = &[""];

/// `Esc` para o codex: medido hoje, o `codex` que se auto-atualizou abre um modal de configuração
/// ("PostCompact hooks … Press esc to go back") e o Enter do handshake **abre** o modal em vez de
/// fechá-lo — o pedido da prova caía dentro do diálogo e o arquivo nunca aparecia. Com o Esc o
/// mesmo pedido escreveu `CODEX_OK` em 5s. Handshake é por runtime porque o diálogo é de cada CLI.
const ESC: &[&str] = &["\u{1b}"];

pub const RUNTIMES: &[RuntimeSpec] = &[
    RuntimeSpec { id: "shell", command: "pwsh.exe", unrestricted_args: &[], proof_driver: ProofDriver::ShellCommand, boot_inputs: &[] },
    RuntimeSpec { id: "claude", command: "claude", unrestricted_args: &["--dangerously-skip-permissions"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "codex", command: "codex", unrestricted_args: &["--dangerously-bypass-approvals-and-sandbox"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ESC },
    RuntimeSpec { id: "opencode", command: "opencode", unrestricted_args: &["--dangerously-skip-permissions"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "antigravity", command: "antigravity", unrestricted_args: &["--dangerously-skip-permissions"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "cursor", command: "cursor", unrestricted_args: &["--force"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "copilot", command: "github-copilot", unrestricted_args: &["--allow-all"], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "mimo", command: "mimo", unrestricted_args: &[], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
    RuntimeSpec { id: "freebuff", command: "freebuff", unrestricted_args: &[], proof_driver: ProofDriver::AgentPrompt, boot_inputs: ENTER },
];

pub fn spec(id: &str) -> Option<&'static RuntimeSpec> {
    RUNTIMES.iter().find(|runtime| runtime.id == id)
}

/// Handshake de boot do runtime (vazio para id desconhecido, que a rota de prova já recusa antes).
pub fn boot_inputs(id: &str) -> &'static [&'static str] {
    spec(id).map(|runtime| runtime.boot_inputs).unwrap_or(&[])
}

/// Nome do arquivo da prova (`proof-<id>.txt`) e o conteúdo esperado em cada etapa. O contrato é
/// texto literal para a verificação ser leitura de arquivo, não interpretação de saída de CLI.
pub fn proof_file_name(id: &str) -> String {
    format!("proof-{id}.txt")
}

pub fn proof_expected(id: &str, stage: ProofStage) -> String {
    match stage {
        ProofStage::Spawn => format!("{}_OK", id.to_uppercase()),
        ProofStage::Steer => format!("{}_STEER_OK", id.to_uppercase()),
    }
}

/// O que o runtime recebe para cumprir a prova. Um pedido por etapa: primeiro cria o arquivo, depois
/// (sob steer) altera o mesmo arquivo — o que separa "o agente subiu" de "o agente obedece uma
/// segunda instrução na mesma sessão". O texto é escolhido pelo driver do runtime; id desconhecido
/// cai em prosa (a rota de prova já recusa id fora do registry antes de chegar aqui).
pub fn proof_prompt(id: &str, dir: &str, stage: ProofStage) -> String {
    let file = proof_file_name(id);
    let content = proof_expected(id, stage);
    let path = format!("{dir}\\{file}");
    match spec(id).map(|runtime| runtime.proof_driver).unwrap_or(ProofDriver::AgentPrompt) {
        ProofDriver::AgentPrompt => match stage {
            ProofStage::Spawn => format!(
                "Crie o arquivo {path} contendo exatamente o texto {content} e nada mais. Responda somente OK."
            ),
            ProofStage::Steer => format!(
                "Altere o arquivo {path} para conter exatamente o texto {content} e nada mais. Responda somente OK."
            ),
        },
        ProofDriver::ShellCommand => format!(
            "Set-Content -LiteralPath '{path}' -Value '{content}' -NoNewline"
        ),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStage {
    Spawn,
    Steer,
}

/// O registro de uma prova. `ok` só é verdadeiro com as duas etapas medidas no disco; `args` são os
/// `extra_args` com que o runtime foi de fato dirigido (auditável); `agent_id` é a sessão que fez o
/// efeito.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRecord {
    pub runtime: String,
    #[serde(default)]
    pub spawn_ok: bool,
    #[serde(default)]
    pub steer_ok: bool,
    pub agent_id: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Handshake de boot efetivamente enviado antes do pedido (auditável: se um runtime novo exigir
    /// outra tecla, o registro mostra com o que a prova dele foi medida).
    #[serde(default)]
    pub boot_inputs: Vec<String>,
    pub dir: String,
    pub proved_at_ms: u64,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub content: String,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
    /// Rastro legível das últimas linhas da sessão de prova (o scrollback morre com a sessão): é o
    /// que explica a reprovação sem precisar reproduzir a corrida.
    #[serde(default)]
    pub output_tail: String,
}

impl ProofRecord {
    pub fn new(runtime: &str, agent_id: &str, args: Vec<String>, dir: &str) -> Self {
        Self {
            runtime: runtime.to_string(),
            spawn_ok: false,
            steer_ok: false,
            agent_id: agent_id.to_string(),
            args,
            boot_inputs: Vec::new(),
            dir: dir.to_string(),
            proved_at_ms: crate::provider_common::now_ms(),
            file: proof_file_name(runtime),
            content: String::new(),
            ok: false,
            detail: String::new(),
            output_tail: String::new(),
        }
    }
}

pub type ProofMap = BTreeMap<String, ProofRecord>;

pub fn proofs_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::profile_data_dir(app)?.join("runtime-proofs.json"))
}

/// Carrega os registros de prova. Arquivo ausente é mapa vazio (nada provado ainda); arquivo
/// ilegível não derruba o app nem vira prova: devolve vazio, porque prova que não pode ser lida não
/// autoriza execução.
pub fn load_proofs(app: &AppHandle) -> ProofMap {
    match proofs_path(app) {
        Ok(path) => load_proofs_at(&path),
        Err(_) => ProofMap::new(),
    }
}

pub fn load_proofs_at(path: &Path) -> ProofMap {
    let Ok(content) = std::fs::read_to_string(path) else {
        return ProofMap::new();
    };
    serde_json::from_str::<ProofMap>(&content).unwrap_or_default()
}

pub fn record_proof(app: &AppHandle, record: &ProofRecord) -> Result<ProofRecord, String> {
    let path = proofs_path(app)?;
    record_proof_at(&path, record)
}

/// Grava o registro no disco e devolve o que ficou gravado (o mapa é relido antes para não perder
/// prova de outro runtime gravada por outro pedido).
pub fn record_proof_at(path: &Path, record: &ProofRecord) -> Result<ProofRecord, String> {
    let mut proofs = load_proofs_at(path);
    let merged = match proofs.get(&record.runtime) {
        Some(previous) => ProofRecord {
            spawn_ok: previous.spawn_ok || record.spawn_ok,
            steer_ok: previous.steer_ok || record.steer_ok,
            ..record.clone()
        },
        None => record.clone(),
    };
    let merged = ProofRecord {
        ok: merged.spawn_ok && merged.steer_ok,
        ..merged
    };
    proofs.insert(merged.runtime.clone(), merged.clone());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let serialized = serde_json::to_string_pretty(&proofs).map_err(|error| error.to_string())?;
    std::fs::write(path, format!("{serialized}\n")).map_err(|error| error.to_string())?;
    Ok(merged)
}

/// Executável pelo control plane só com efeito comprovado — o predicado que `/agents` publica como
/// `execution_supported` e que o gate do spawn exige. Recebe o mapa já carregado porque quem responde
/// o `/agents` lê o arquivo UMA vez para todos os runtimes.
pub fn proof_ok(proofs: &ProofMap, id: &str) -> bool {
    proofs.get(id).map(|proof| proof.ok).unwrap_or(false)
}

/// Motivo da recusa do spawn, ou `None` quando pode. Função pura sobre o mapa para o teste exercitar
/// a regra sem AppHandle; as mensagens dizem o que falta em vez de um "não pode" genérico.
pub fn spawn_denied_reason_from(
    proofs: &ProofMap,
    available: bool,
    id: &str,
) -> Option<String> {
    let Some(runtime) = spec(id) else {
        return Some(format!("agent_runtime_not_supported:{id}"));
    };
    if !available {
        return Some(format!("runtime_unavailable:{}", runtime.command));
    }
    match proofs.get(id) {
        Some(proof) if proof.ok => None,
        Some(proof) => Some(format!(
            "runtime_without_proof:{id} (spawn={} steer={})",
            proof.spawn_ok, proof.steer_ok
        )),
        None => Some(format!("runtime_without_proof:{id}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O contrato da prova é texto literal: nome do arquivo e conteúdo de cada etapa. Se isto mudar,
    /// o runner e o registro precisam mudar junto — por isso o teste fixa o contrato.
    #[test]
    fn proof_contract_is_literal_and_per_runtime() {
        assert_eq!(proof_file_name("claude"), "proof-claude.txt");
        assert_eq!(proof_file_name("antigravity"), "proof-antigravity.txt");
        assert_eq!(proof_expected("claude", ProofStage::Spawn), "CLAUDE_OK");
        assert_eq!(proof_expected("claude", ProofStage::Steer), "CLAUDE_STEER_OK");
        assert_eq!(proof_expected("antigravity", ProofStage::Steer), "ANTIGRAVITY_STEER_OK");

        let prompt = proof_prompt("codex", "C:\\temp\\prova", ProofStage::Spawn);
        assert!(prompt.contains("C:\\temp\\prova\\proof-codex.txt"), "{prompt}");
        assert!(prompt.contains("CODEX_OK"), "{prompt}");
        let steer = proof_prompt("codex", "C:\\temp\\prova", ProofStage::Steer);
        assert!(steer.contains("CODEX_STEER_OK"), "{steer}");
        assert!(steer.contains("proof-codex.txt"), "{steer}");
    }

    /// O shell não tem LLM: a prova dele é o comando literal, não prosa. Este teste roda o texto do
    /// driver num pwsh de verdade (diretório e arquivo reais) e confere o conteúdo no disco — se a
    /// prosa voltasse para o shell, o pwsh tentaria executar a frase e o arquivo não apareceria.
    #[test]
    fn the_shell_driver_is_a_command_that_really_writes_the_file() {
        assert_eq!(
            spec("shell").map(|runtime| runtime.proof_driver),
            Some(ProofDriver::ShellCommand)
        );
        for id in ["claude", "codex", "opencode", "antigravity"] {
            assert_eq!(
                spec(id).map(|runtime| runtime.proof_driver),
                Some(ProofDriver::AgentPrompt),
                "{id} é CLI de agente: a prova vai em prosa"
            );
        }

        let prompt = proof_prompt("shell", "C:\\temp\\prova", ProofStage::Spawn);
        assert!(prompt.contains("Set-Content"), "{prompt}");
        assert!(!prompt.contains("Crie o arquivo"), "shell não interpreta prosa: {prompt}");

        let Some(pwsh) = crate::cli_resolver::find_windows_cli_launcher("pwsh.exe") else {
            eprintln!("SKIP: pwsh.exe não está instalado nesta máquina — o comando do shell não foi executado");
            return;
        };
        let dir = std::env::temp_dir().join(format!("alethe-shell-proof-{}", nanoid::nanoid!(8)));
        std::fs::create_dir_all(&dir).expect("criar diretório real");
        let dir_str = dir.to_string_lossy().into_owned();

        for stage in [ProofStage::Spawn, ProofStage::Steer] {
            let command = proof_prompt("shell", &dir_str, stage);
            let output = std::process::Command::new(&pwsh)
                .arg("-NoProfile")
                .arg("-Command")
                .arg(&command)
                .output()
                .expect("rodar o pwsh real");
            assert!(
                output.status.success(),
                "o comando da prova falhou: {command} / {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let written = std::fs::read_to_string(dir.join(proof_file_name("shell")))
                .expect("o arquivo da prova tem que existir");
            assert_eq!(written.trim(), proof_expected("shell", stage), "etapa {stage:?}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// O perfil irrestrito é espelho da tabela do app (`src/lib/types.ts`) — inclusive o `shell`,
    /// que não precisa de flag. Um runtime novo aqui sem a flag certa reprova a prova, não o usuário.
    #[test]
    fn unrestricted_profile_mirrors_the_app_table() {
        let flags: Vec<(&str, &[&str])> = RUNTIMES
            .iter()
            .map(|runtime| (runtime.id, runtime.unrestricted_args))
            .collect();
        assert!(flags.contains(&("claude", &["--dangerously-skip-permissions"][..])));
        assert!(flags.contains(&("codex", &["--dangerously-bypass-approvals-and-sandbox"][..])));
        assert!(flags.contains(&("opencode", &["--dangerously-skip-permissions"][..])));
        assert!(flags.contains(&("antigravity", &["--dangerously-skip-permissions"][..])));
        assert!(flags.contains(&("shell", &[][..])));
        // o que o app não conhece como executável não inventa flag
        assert!(spec("mimo").is_some_and(|runtime| runtime.unrestricted_args.is_empty()));
    }

    /// A regra do spawn é pura e falha fechada: sem prova não executa, e o motivo diz o que falta.
    #[test]
    fn spawn_gate_requires_proof_and_says_why() {
        let mut proofs = ProofMap::new();
        assert_eq!(
            spawn_denied_reason_from(&proofs, true, "antigravity").as_deref(),
            Some("runtime_without_proof:antigravity")
        );
        assert_eq!(
            spawn_denied_reason_from(&proofs, false, "claude").as_deref(),
            Some("runtime_unavailable:claude")
        );
        assert_eq!(
            spawn_denied_reason_from(&proofs, true, "desconhecido").as_deref(),
            Some("agent_runtime_not_supported:desconhecido")
        );

        // meia prova (só spawn) ainda não executa, e o motivo mostra qual etapa faltou
        proofs.insert(
            "claude".to_string(),
            ProofRecord {
                ok: false,
                spawn_ok: true,
                steer_ok: false,
                ..ProofRecord::new("claude", "agent-1", vec![], "C:\\temp")
            },
        );
        let reason = spawn_denied_reason_from(&proofs, true, "claude").expect("meia prova recusa");
        assert!(reason.contains("spawn=true steer=false"), "{reason}");

        proofs.insert(
            "claude".to_string(),
            ProofRecord {
                ok: true,
                spawn_ok: true,
                steer_ok: true,
                ..ProofRecord::new("claude", "agent-1", vec![], "C:\\temp")
            },
        );
        assert_eq!(spawn_denied_reason_from(&proofs, true, "claude"), None);
    }

    /// Um registro gravado por uma versão anterior do app (sem os campos novos) continua sendo lido:
    /// o arquivo que está no disco foi escrito antes de `boot_inputs`/`output_tail` existirem, e prova
    /// que não lê é prova que não autoriza execução. O teste roda contra o formato real do arquivo,
    /// não contra um JSON inventado.
    #[test]
    fn a_record_written_before_the_new_fields_is_still_read() {
        let dir = std::env::temp_dir().join(format!("alethe-proofs-old-{}", nanoid::nanoid!(8)));
        std::fs::create_dir_all(&dir).expect("criar diretório real");
        let path = dir.join("runtime-proofs.json");
        let old = r#"{
  "shell": {
    "runtime": "shell",
    "spawn_ok": true,
    "steer_ok": true,
    "agent_id": "proof-shell-RAY87T",
    "args": [],
    "dir": "C:\\Users\\Lucas Moura\\AppData\\Local\\Temp\\alethe-proof-task5\\shell",
    "proved_at_ms": 1790037459303,
    "file": "C:\\Users\\Lucas Moura\\AppData\\Local\\Temp\\alethe-proof-task5\\shell\\proof-shell.txt",
    "content": "SHELL_STEER_OK",
    "ok": true,
    "detail": "spawn e steer medidos no disco"
  }
}"#;
        std::fs::write(&path, old).expect("gravar o registro antigo");

        let proofs = load_proofs_at(&path);
        let record = proofs.get("shell").expect("o registro antigo tem que ser lido");
        assert!(record.ok, "ok=true do arquivo antigo tem que sobreviver");
        assert_eq!(record.content, "SHELL_STEER_OK");
        assert!(record.boot_inputs.is_empty(), "campo novo ausente vira vazio");
        assert!(record.output_tail.is_empty());
        assert!(proof_ok(&proofs, "shell"), "e o gate tem que aceitar o shell");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// O registro é arquivo de verdade num diretório de verdade: as duas etapas se somam (spawn +
    /// steer = ok), `ok` é derivado das etapas e não aceito do chamador, e arquivo ilegível não vira
    /// prova.
    #[test]
    fn proof_store_merges_stages_in_a_real_file() {
        let dir = std::env::temp_dir().join(format!("alethe-proofs-{}", nanoid::nanoid!(8)));
        std::fs::create_dir_all(&dir).expect("criar diretório real");
        let path = dir.join("runtime-proofs.json");

        let first = ProofRecord {
            spawn_ok: true,
            ok: true, // mentira do chamador: o merge derruba
            ..ProofRecord::new("claude", "agent-1", vec!["--flag".into()], "C:\\temp")
        };
        let stored = record_proof_at(&path, &first).expect("gravar");
        assert!(stored.spawn_ok && !stored.steer_ok && !stored.ok, "ok não vem do chamador");

        let second = ProofRecord {
            steer_ok: true,
            ..ProofRecord::new("claude", "agent-1", vec!["--flag".into()], "C:\\temp")
        };
        let merged = record_proof_at(&path, &second).expect("gravar etapa 2");
        assert!(merged.ok, "spawn + steer = provado");

        // outro runtime no mesmo arquivo não perde o primeiro
        let outro = ProofRecord {
            spawn_ok: true,
            steer_ok: true,
            ..ProofRecord::new("shell", "agent-2", vec![], "C:\\temp")
        };
        record_proof_at(&path, &outro).expect("gravar outro runtime");
        let proofs = load_proofs_at(&path);
        assert_eq!(proofs.len(), 2);
        assert!(proofs["claude"].ok && proofs["shell"].ok);
        assert_eq!(proofs["claude"].args, vec!["--flag".to_string()]);

        // arquivo ilegível não autoriza nada
        std::fs::write(&path, "{isso não é json").expect("escrever lixo");
        assert!(load_proofs_at(&path).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
