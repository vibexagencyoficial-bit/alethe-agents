import { beforeEach, describe, expect, it } from 'vitest'

import { useProjectsStore } from '../stores/projectsStore'
import { openControlPane, runtimeToAgentType } from './controlPaneOpen'
import { makeDefaultTerminal } from './terminalFactory'

// O componente real, não um dublê: o que este teste precisa provar é que o pedido do control plane
// termina num terminal do store de verdade, com a aba ligada ao pty id que veio no pedido. Um
// objeto imitando o store provaria só o imitador.
function reset() {
  useProjectsStore.setState({ projects: [], activeProjectId: null, hydrated: false })
}

function firstTabOf(terminalId: string) {
  const project = useProjectsStore
    .getState()
    .projects.find((candidate) => candidate.terminals.some((terminal) => terminal.id === terminalId))
  const terminal = project?.terminals.find((candidate) => candidate.id === terminalId)
  return terminal?.tabs[0]
}

describe('pane do control plane', () => {
  beforeEach(reset)

  it('liga o pane à sessão que já existe em vez de subir outra', () => {
    const project = useProjectsStore.getState().createProject({ name: 'p1', defaultCwd: 'C:\\proj' })

    const opened = openControlPane(
      { pty_id: 'agent-9f3', runtime: 'codex', cwd: 'C:\\proj' },
      useProjectsStore.getState(),
    )

    expect(opened?.projectId).toBe(project.id)
    expect(opened?.agent).toBe('codex')
    // o essencial: a aba aponta para a sessão REAL que o control plane subiu
    const tab = firstTabOf(opened!.terminalId)
    expect(tab?.ptyId).toBe('agent-9f3')
    expect(tab?.type).toBe('codex')
    // e o projeto não ganhou um terminal extra: o pane é o mesmo que o chamador pediu
    expect(useProjectsStore.getState().projects[0].terminals).toHaveLength(1)
  })

  it('cria projeto quando o diretório da sessão ainda não é de nenhum', () => {
    const opened = openControlPane(
      { pty_id: 'pty-1', runtime: 'shell', cwd: 'C:\\novo-projeto' },
      useProjectsStore.getState(),
    )

    const projects = useProjectsStore.getState().projects
    expect(projects).toHaveLength(1)
    expect(projects[0].name).toBe('novo-projeto')
    expect(projects[0].defaultCwd).toBe('C:\\novo-projeto')
    expect(opened?.projectId).toBe(projects[0].id)
    expect(firstTabOf(opened!.terminalId)?.ptyId).toBe('pty-1')
  })

  it('sem pty_id não abre pane: sessão nenhuma para mostrar', () => {
    useProjectsStore.getState().createProject({ name: 'p1', defaultCwd: 'C:\\proj' })

    expect(
      openControlPane({ pty_id: '  ', runtime: 'codex', cwd: 'C:\\proj' }, useProjectsStore.getState()),
    ).toBeNull()
    expect(useProjectsStore.getState().projects[0].terminals).toHaveLength(0)
  })

  it('runtime fora da lista da janela não vira pane de agente errado', () => {
    expect(
      openControlPane(
        { pty_id: 'pty-1', runtime: 'harness-inexistente', cwd: 'C:\\proj' },
        useProjectsStore.getState(),
      ),
    ).toBeNull()
    expect(useProjectsStore.getState().projects).toHaveLength(0)
  })

  it('sem cwd o pane vai para o projeto ativo, não para um projeto órfão', () => {
    const store = useProjectsStore.getState()
    store.createProject({ name: 'p1', defaultCwd: 'C:\\proj' })
    const second = store.createProject({ name: 'p2', defaultCwd: 'C:\\outro' })
    useProjectsStore.setState({ activeProjectId: second.id })

    const opened = openControlPane({ pty_id: 'pty-1', runtime: 'claude', cwd: '' }, useProjectsStore.getState())

    expect(opened?.projectId).toBe(second.id)
    expect(useProjectsStore.getState().projects).toHaveLength(2)
    expect(firstTabOf(opened!.terminalId)?.cwd).toBe('C:\\outro')
  })

  it('os ids do registry são os mesmos nomes de agente da janela', () => {
    expect(runtimeToAgentType('shell')).toBe('shell')
    expect(runtimeToAgentType('  Antigravity ')).toBe('antigravity')
    expect(runtimeToAgentType('github-copilot')).toBeNull()
  })
})

describe('aba com sessão existente', () => {
  it('a fábrica respeita o ptyId que veio no pedido de pane', () => {
    const terminal = makeDefaultTerminal({
      name: 'Codex',
      cwd: 'C:\\proj',
      firstTab: { type: 'codex', cwd: 'C:\\proj', ptyId: 'agent-9f3' },
    })
    expect(terminal.tabs[0].ptyId).toBe('agent-9f3')
  })

  it('sem ptyId a aba nasce sem sessão (o pane sobe a sua, como antes)', () => {
    const terminal = makeDefaultTerminal({
      name: 'Codex',
      cwd: 'C:\\proj',
      firstTab: { type: 'codex', cwd: 'C:\\proj' },
    })
    expect(terminal.tabs[0].ptyId).toBeNull()
  })
})
