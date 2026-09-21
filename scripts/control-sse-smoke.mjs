#!/usr/bin/env node
// Smoke real do stream do control plane: sobe agentes de verdade pelo HTTP, escreve no PTY e confere
// a sequência que sai em `/control/v1/events`. Nada é simulado — servidor real do app, socket real,
// PTY real (ConPTY), SSE real; o único insumo que o script não produz é o token, que vem do
// pareamento com aprovação na janela (Task 1).
//
// Uso:
//   node scripts/control-sse-smoke.mjs --token <token> [--base http://127.0.0.1:9123/control/v1]
//                                       [--evidence <arquivo.json>] [--shell pwsh.exe]
//
// O que ele prova, na ordem:
//   1. `agent.started` sai quando o PTY de verdade nasce, com o envelope do control plane
//      (`correlation_id`/`task_id`/`agent_id` + payload em `data`);
//   2. `agent.working` sai no send, com `message_bytes` (o texto do usuário NÃO vai no evento);
//   3. `terminal.output` sai com volume (`bytes`/`dropped_bytes`), não com o texto;
//   4. `exit` 0 → `agent.completed` com `exit_code` 0 e teardown `exited`; `exit 3` → `agent.failed`
//      com `exit_code` 3; `stop` nosso → `agent.stopped` com teardown `killed`;
//   5. o marcador escrito no terminal EXISTE no scrollback (rota autenticada de output, lido
//      enquanto o agente vive) e NÃO aparece em nenhum frame do stream — é o que separa "não vazou"
//      de "não aconteceu".

import { mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

const argv = process.argv.slice(2)
function flag(name, fallback = null) {
  const at = argv.indexOf(`--${name}`)
  return at >= 0 && at + 1 < argv.length ? argv[at + 1] : fallback
}

const token = flag('token')
const evidencePath = flag('evidence')
// vazio = deixa o app resolver o launcher pelo PATH (é o caminho de produção); preenchido = força
// um binário, útil quando o `pwsh` do PATH é alias e não arquivo.
const shellExe = flag('shell', '')
if (!token) {
  console.error('--token é obrigatório (pareie com aprovação na janela e passe o access_token)')
  process.exit(2)
}

const host = '127.0.0.1'
const runId = Math.random().toString(36).slice(2, 8)
const shellCwd = join(tmpdir(), `alethe-sse-smoke-${runId}`)
mkdirSync(shellCwd, { recursive: true })

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function discoverBase() {
  const explicit = flag('base')
  if (explicit) return explicit.replace(/\/$/, '')
  for (let port = 9123; port <= 9132; port++) {
    try {
      const response = await fetch(`http://${host}:${port}/control/v1/health`)
      if (!response.ok) continue
      const health = await response.json()
      if (health.service === 'alethe-control' && health.ready && health.bind === host) {
        return `http://${host}:${port}/control/v1`
      }
    } catch {
      // porta fechada: segue para a próxima
    }
  }
  throw new Error('control plane não encontrado em 9123-9132 (o app está rodando?)')
}

async function call(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  let payload = null
  try {
    payload = text ? JSON.parse(text) : null
  } catch {
    payload = text
  }
  return { status: response.status, payload }
}

/** Consome o SSE e acumula os frames parseados; o bombeamento roda em paralelo até o fim do processo. */
function openStream(base) {
  const frames = []
  const state = { error: null }
  // `headers` resolve quando os cabeçalhos chegam (não quando o stream fecha, que é nunca): é o
  // sinal de que o stream abriu de verdade e os frames já podem ser publicados do outro lado.
  const headers = (async () => {
    const response = await fetch(`${base}/events`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
    })
    if (!response.ok) throw new Error(`SSE recusado: HTTP ${response.status}`)
    pump(response)
    return response.status
  })()
  function pump(response) {
    ;(async () => {
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        let boundary
        while ((boundary = buffer.indexOf('\n\n')) >= 0) {
          const raw = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          const lines = raw.split('\n')
          const event = lines.find((line) => line.startsWith('event: '))?.slice(7)
          const data = lines.find((line) => line.startsWith('data: '))?.slice(6)
          if (!event) continue
          let parsed = null
          try {
            parsed = data ? JSON.parse(data) : null
          } catch {
            parsed = data
          }
          frames.push({ event, data: parsed, raw })
        }
      }
    })().catch((error) => {
      state.error = error
    })
  }
  return { frames, state, headers }
}

/**
 * O `data:` do frame é o ENVELOPE do control plane — `{timestamp_ms, correlation_id, task_id,
 * agent_id, data}` — e o payload do evento está em `envelope.data`. Ler o envelope como se fosse o
 * payload foi o erro do primeiro driver deste smoke: as asserções falhavam com o evento certo na
 * tela.
 */
const eventPayload = (frame) => {
  const payload = frame?.data?.data
  return payload && typeof payload === 'object' ? payload : {}
}

async function waitFor(frames, predicate, description, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const found = [...frames].reverse().find(predicate)
    if (found) return found
    await sleep(40)
  }
  throw new Error(
    `timeout esperando ${description}; eventos vistos: ${frames.map((frame) => frame.event).join(', ') || '(nenhum)'}`,
  )
}

/** O scrollback é liberado por flush com debounce: espera o marcador aparecer em vez de exigir na hora. */
async function waitForScrollback(base, id, needle, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs
  let last = null
  while (Date.now() < deadline) {
    last = await call(base, 'GET', `/agents/${id}/output`)
    if (last.status === 200 && String(last.payload?.output ?? '').includes(needle)) return last
    await sleep(200)
  }
  return last
}

const checks = []
function check(name, ok, detail) {
  checks.push({ name, ok: Boolean(ok), detail })
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : ` — ${detail}`}`)
}

function spawnBody(id) {
  return {
    agent: 'shell',
    id,
    cwd: shellCwd,
    cols: 100,
    rows: 30,
    ...(shellExe ? { launcher_override: shellExe } : {}),
  }
}

async function main() {
  const base = await discoverBase()
  console.log(`control plane: ${base}`)
  const health = await call(base, 'GET', '/health')
  if (health.status !== 200) throw new Error(`health HTTP ${health.status}`)

  const stream = openStream(base)
  await stream.headers
  const frames = stream.frames

  const okId = `t4-ok-${runId}`
  const failId = `t4-fail-${runId}`
  const stopId = `t4-stop-${runId}`

  // --- 1. agente que termina bem: started → working → completed -------------------------------
  const okMessage = 'Write-Output ALETHE_T4_OK\r\n'
  const spawnOk = await call(base, 'POST', '/agents/spawn', spawnBody(okId))
  check('spawn do agente real responde 201', spawnOk.status === 201, `HTTP ${spawnOk.status}: ${JSON.stringify(spawnOk.payload)}`)
  check('spawn responde com o id pedido', spawnOk.payload?.agent_id === okId, JSON.stringify(spawnOk.payload))

  const started = await waitFor(frames, (frame) => frame.event === 'agent.started' && frame.data?.agent_id === okId, `agent.started de ${okId}`)
  check('agent.started traz o id no envelope e no payload', started.data?.agent_id === okId && eventPayload(started).agent_id === okId, JSON.stringify(started.data))
  check('o envelope do stream é o do control plane (correlation_id/task_id/timestamp)', typeof started.data?.correlation_id === 'string' && started.data.correlation_id.startsWith('ctrl-') && started.data.correlation_id.length > 5 && 'task_id' in started.data && typeof started.data?.timestamp_ms === 'number', JSON.stringify(started.data))
  check('agent.started diz de onde veio', eventPayload(started).source === 'real Alethe PTY', JSON.stringify(eventPayload(started)))

  const sendOk = await call(base, 'POST', `/agents/${okId}/send`, { message: okMessage })
  check('send responde 200 accepted', sendOk.status === 200 && sendOk.payload?.accepted === true, `HTTP ${sendOk.status}: ${JSON.stringify(sendOk.payload)}`)

  const working = await waitFor(frames, (frame) => frame.event === 'agent.working' && frame.data?.agent_id === okId, `agent.working de ${okId}`)
  check('agent.working diz o tamanho da mensagem, não o texto', eventPayload(working).message_bytes === Buffer.byteLength(okMessage), JSON.stringify(eventPayload(working)))
  check('agent.working diz que veio de send', eventPayload(working).source === 'send', JSON.stringify(eventPayload(working)))

  const output = await waitFor(frames, (frame) => frame.event === 'terminal.output' && frame.data?.agent_id === okId, `terminal.output de ${okId}`)
  check('terminal.output sai com volume, não com texto', typeof eventPayload(output).bytes === 'number' && eventPayload(output).bytes > 0 && 'dropped_bytes' in eventPayload(output), JSON.stringify(eventPayload(output)))

  // o marcador existe de verdade no terminal — sem isso "não vazou" seria vácuo. Lido AGORA, com o
  // agente vivo: depois que ele termina a sessão sai do mapa e a rota responde 404 (por desenho).
  const scrollback = await waitForScrollback(base, okId, 'ALETHE_T4_OK')
  check('o marcador existe no scrollback (rota autenticada), com o agente vivo', scrollback?.status === 200 && String(scrollback.payload?.output ?? '').includes('ALETHE_T4_OK'), `HTTP ${scrollback?.status}`)

  const exitOk = await call(base, 'POST', `/agents/${okId}/send`, { message: 'exit\r\n' })
  check('send do exit responde 200', exitOk.status === 200, `HTTP ${exitOk.status}`)
  const completed = await waitFor(frames, (frame) => frame.event === 'agent.completed' && frame.data?.agent_id === okId, `agent.completed de ${okId}`)
  check('exit 0 vira agent.completed com exit_code 0', eventPayload(completed).exit_code === 0, JSON.stringify(eventPayload(completed)))
  check('agent.completed diz que o teardown foi do próprio processo', eventPayload(completed).teardown === 'exited', JSON.stringify(eventPayload(completed)))

  // --- 2. agente que termina mal: exit 3 → failed ---------------------------------------------
  const spawnFail = await call(base, 'POST', '/agents/spawn', spawnBody(failId))
  check('spawn do segundo agente responde 201', spawnFail.status === 201, `HTTP ${spawnFail.status}: ${JSON.stringify(spawnFail.payload)}`)
  await waitFor(frames, (frame) => frame.event === 'agent.started' && frame.data?.agent_id === failId, `agent.started de ${failId}`)
  await call(base, 'POST', `/agents/${failId}/send`, { message: 'exit 3\r\n' })
  const failed = await waitFor(frames, (frame) => frame.event === 'agent.failed' && frame.data?.agent_id === failId, `agent.failed de ${failId}`)
  check('exit 3 vira agent.failed com exit_code 3', eventPayload(failed).exit_code === 3, JSON.stringify(eventPayload(failed)))
  check('agent.failed traz o código real, não um código fixo', eventPayload(failed).teardown === 'exited' && eventPayload(failed).exit_code !== 1, JSON.stringify(eventPayload(failed)))

  // --- 3. agente parado por nós: stop → stopped -----------------------------------------------
  const spawnStop = await call(base, 'POST', '/agents/spawn', spawnBody(stopId))
  check('spawn do terceiro agente responde 201', spawnStop.status === 201, `HTTP ${spawnStop.status}: ${JSON.stringify(spawnStop.payload)}`)
  await waitFor(frames, (frame) => frame.event === 'agent.started' && frame.data?.agent_id === stopId, `agent.started de ${stopId}`)
  const stoppedCall = await call(base, 'POST', `/agents/${stopId}/stop`)
  check('stop responde 200', stoppedCall.status === 200, `HTTP ${stoppedCall.status}: ${JSON.stringify(stoppedCall.payload)}`)
  const stopped = await waitFor(frames, (frame) => frame.event === 'agent.stopped' && frame.data?.agent_id === stopId, `agent.stopped de ${stopId}`)
  check('parada nossa vira agent.stopped com teardown killed', eventPayload(stopped).teardown === 'killed', JSON.stringify(eventPayload(stopped)))

  // --- 4. ordem e conteúdo ---------------------------------------------------------------------
  const mine = frames.filter((frame) => [okId, failId, stopId].includes(frame.data?.agent_id))
  const sequence = mine.filter((frame) => frame.data?.agent_id === okId).map((frame) => frame.event)
  const order = sequence.join(' → ')
  const firstStarted = sequence.indexOf('agent.started')
  const firstWorking = sequence.indexOf('agent.working')
  const firstOutput = sequence.indexOf('terminal.output')
  const endAt = sequence.findIndex((event) => ['agent.completed', 'agent.failed', 'agent.stopped'].includes(event))
  const afterEnd = sequence.slice(endAt + 1).filter((event) => event !== 'terminal.output')
  check(
    `a sequência de ${okId} é started → working → terminal.output → completed, sem evento depois do fim`,
    firstStarted === 0 && firstWorking > firstStarted && firstOutput > firstWorking && endAt > firstOutput && sequence[endAt] === 'agent.completed' && afterEnd.length === 0,
    order,
  )
  check('o agente que falhou não recebeu event de fim bem-sucedido', !mine.some((frame) => frame.data?.agent_id === failId && frame.event === 'agent.completed'), mine.map((frame) => `${frame.data?.agent_id}:${frame.event}`).join(', '))

  const leaked = frames.filter((frame) => JSON.stringify(frame.data ?? '').includes('ALETHE_T4_OK'))
  check('nenhum frame do stream carrega o texto escrito no terminal', leaked.length === 0, JSON.stringify(leaked.map((frame) => frame.raw)))

  const report = {
    ranAt: new Date().toISOString(),
    base,
    agents: { ok: okId, fail: failId, stop: stopId },
    checks,
    passed: checks.every((entry) => entry.ok),
    envelopeExample: frames.find((frame) => frame.event === 'agent.working')?.data ?? null,
    frames: frames.map((frame) => ({ event: frame.event, envelope: frame.data })),
  }
  if (evidencePath) {
    mkdirSync(dirname(evidencePath), { recursive: true })
    writeFileSync(evidencePath, `${JSON.stringify(report, null, 2)}\n`)
    console.log(`evidência: ${evidencePath}`)
  }

  const total = frames.length
  console.log(`\n${checks.filter((entry) => entry.ok).length}/${checks.length} verificações ok · ${total} frames no stream`)
  if (!report.passed) {
    process.exitCode = 1
  }
  process.exit(report.passed ? 0 : 1)
}

main().catch((error) => {
  console.error(`smoke falhou: ${error.message}`)
  process.exit(1)
})
