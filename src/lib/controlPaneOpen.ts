import { planCliOpen } from './cliOpen'
import type { AgentType, Project } from './types'

/**
 * Pane para a sessão que o control plane subiu.
 *
 * O processo já existe: quem o subiu foi o app, a pedido de um cliente externo. Por isso o pane
 * tem de se LIGAR a essa sessão — a `pty_id` viaja no pedido e o `XTermView` atacha nela
 * (`pty_exists` → `attachExistingPty`) em vez de subir o seu próprio processo. Um pane que sobe
 * outra sessão mostraria um processo diferente do que o cliente externo está dirigindo, e o
 * `/terminals` teria duas entradas onde o chamador pediu uma.
 */
export type ControlPaneRequest = {
  pty_id: string
  runtime: string
  cwd: string
}

/** Os ids do registry de runtimes (Rust) são os mesmos `AgentType` da janela. */
const RUNTIME_AGENTS: AgentType[] = [
  'shell',
  'claude',
  'codex',
  'opencode',
  'antigravity',
  'cursor',
  'copilot',
  'mimo',
  'freebuff',
]

export function runtimeToAgentType(runtime: string): AgentType | null {
  const id = runtime.trim().toLowerCase()
  return RUNTIME_AGENTS.find((candidate) => candidate === id) ?? null
}

type ControlPaneStore = {
  projects: Project[]
  activeProjectId: string | null
  createProject: (args: { name: string; defaultCwd: string }) => { id: string }
  createTerminal: (
    projectId: string,
    args: { name: string; cwd: string; firstTab: { type: AgentType; cwd: string; ptyId?: string } },
  ) => { id: string }
  openTerminalWorkspace: (projectId: string, terminalId: string) => void
}

export type ControlPaneOpened = { projectId: string; terminalId: string; agent: AgentType }

/**
 * Abre o pane e devolve o que abriu. `null` quando o pedido não dá pane: sem `pty_id` não há
 * sessão para mostrar (e um pane que sobe o seu próprio processo seria outra sessão), e runtime
 * fora da lista é id que a janela não sabe desenhar. Nos dois casos o chamador externo continua
 * com a sessão viva — o que não aconteceu foi só a janela.
 */
export function openControlPane(
  request: ControlPaneRequest,
  store: ControlPaneStore,
): ControlPaneOpened | null {
  const ptyId = request.pty_id.trim()
  const agent = runtimeToAgentType(request.runtime)
  if (!ptyId || !agent) return null

  // Sem cwd no pedido o pane vai para o projeto ativo: o processo está em algum diretório real
  // (o spawn resolve um quando o pedido não traz nenhum) e inventar um projeto novo para ele
  // separaria a sessão do trabalho em que ela foi pedida.
  const requested = request.cwd.trim()
  const active = store.projects.find((project) => project.id === store.activeProjectId)
  const cwd = requested || active?.defaultCwd || ''

  const plan = cwd ? planCliOpen(cwd, store.projects) : null
  const projectId =
    plan?.kind === 'existing'
      ? plan.projectId
      : (active && !cwd ? active.id : store.createProject({ name: plan?.name ?? agent, defaultCwd: cwd }).id)

  const terminal = store.createTerminal(projectId, {
    name: terminalNameFor(agent),
    cwd,
    firstTab: { type: agent, cwd, ptyId },
  })
  store.openTerminalWorkspace(projectId, terminal.id)
  return { projectId, terminalId: terminal.id, agent }
}

function terminalNameFor(agent: AgentType): string {
  const labels: Record<AgentType, string> = {
    claude: 'Claude',
    codex: 'Codex',
    copilot: 'GitHub Copilot',
    cursor: 'Cursor',
    antigravity: 'Antigravity',
    opencode: 'OpenCode',
    shell: 'Shell',
    mimo: 'Mimo',
    freebuff: 'Freebuff',
  }
  return labels[agent]
}
