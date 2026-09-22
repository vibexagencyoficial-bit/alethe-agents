// Runner da prova de efeito dos runtimes (Task 5 do plano alethe-circuito-completo).
//
// Quem executa o contrato é o APP, não este script: ele chama POST /control/v1/runtimes/{id}/proof
// e o app cria o diretório, sobe o runtime com o perfil irrestrito do registry, manda o pedido de
// spawn, espera o arquivo `proof-<id>.txt` com o conteúdo exato, manda o steer, espera o arquivo
// mudar e registra o resultado. O script só pede, lê o arquivo do disco e confere o que o
// /control/v1/agents passou a dizer — a evidência é o arquivo real, não a resposta HTTP.
//
// Uso:
//   ALETHE_TOKEN_FILE=<arquivo com o token> node scripts/runtime-proof.mjs shell claude codex
//   ALETHE_CONTROL_URL=http://127.0.0.1:9123 (default)
//   --dir <caminho>   diretório da prova (default: %TEMP%\alethe-proof-<id>)
//   --evidence <arq>  grava o JSON com tudo o que foi medido
//
// O token nunca é impresso: só o tamanho e o prefixo do hash, como manda a regra de segredos.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const baseUrl = (process.env.ALETHE_CONTROL_URL || 'http://127.0.0.1:9123').replace(/\/+$/, '');

function loadToken() {
  const inline = process.env.ALETHE_TOKEN;
  if (inline && inline.trim()) return inline.trim();
  const file = process.env.ALETHE_TOKEN_FILE;
  if (!file) throw new Error('sem token: defina ALETHE_TOKEN_FILE ou ALETHE_TOKEN');
  return readFileSync(file, 'utf8').trim();
}

// O pedido de prova é síncrono e pode levar minutos (spawn + steer, cada etapa com teto de 240s):
// o cliente HTTP do Node não pode cortar a conexão antes disso, então o timeout é explícito.
//
// Nada de `Connection: close` aqui: com esse header e o agente keep-alive do Node, o pedido seguinte
// reusa um socket que o servidor já fechou e morre com ECONNRESET na hora — foi assim que este
// runner acusou o app de resetar a conexão enquanto o app respondia 200 para o mesmo pedido.
function call(method, path, { token, body, timeoutMs = 900000 } = {}) {
  const url = new URL(baseUrl + path);
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch {
            parsed = { raw };
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timeout de ${timeoutMs}ms em ${method} ${path}`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex').slice(0, 16);
}

function proofFile(dir, id) {
  return join(dir, `proof-${id}.txt`);
}

const args = process.argv.slice(2);
const dirFlag = args.indexOf('--dir');
const evidenceFlag = args.indexOf('--evidence');
const explicitDir = dirFlag >= 0 ? args[dirFlag + 1] : null;
const evidencePath = evidenceFlag >= 0 ? args[evidenceFlag + 1] : null;
const ids = args.filter((arg, index) => {
  if (arg.startsWith('--')) return false;
  if (dirFlag >= 0 && index === dirFlag + 1) return false;
  if (evidenceFlag >= 0 && index === evidenceFlag + 1) return false;
  return true;
});

if (ids.length === 0) {
  console.error('uso: node scripts/runtime-proof.mjs <runtime> [runtime...] [--dir <caminho>] [--evidence <arquivo>]');
  process.exit(2);
}

const token = loadToken();
console.log(`[proof] token len=${token.length} sha=${sha256(token)} base=${baseUrl}`);

const before = await call('GET', '/control/v1/agents', { token, timeoutMs: 30000 });
const beforeById = new Map((before.body?.agents ?? []).map((agent) => [agent.id, agent]));
console.log(`[proof] /agents antes: ${[...beforeById.values()].map((a) => `${a.id}=${a.execution_supported}`).join(' ')}`);

const results = [];
for (const id of ids) {
  const dir = explicitDir ? join(explicitDir, id) : join(tmpdir(), `alethe-proof-${id}`);
  mkdirSync(dir, { recursive: true });
  console.log(`\n[proof] ${id}: POST /control/v1/runtimes/${id}/proof dir=${dir}`);
  const started = Date.now();
  let response;
  try {
    response = await call('POST', `/control/v1/runtimes/${id}/proof`, { token, body: { dir } });
  } catch (error) {
    const elapsed = Date.now() - started;
    console.error(`[proof] ${id}: falha de transporte em ${(elapsed / 1000).toFixed(1)}s: ${error.message}`);
    results.push({ runtime: id, dir, transport_error: error.message, elapsed_ms: elapsed });
    continue;
  }
  const elapsed = Date.now() - started;
  const proof = response.body?.proof ?? null;
  const file = proofFile(dir, id);
  const onDisk = existsSync(file) ? readFileSync(file, 'utf8') : null;

  console.log(
    `[proof] ${id}: HTTP ${response.status} em ${(elapsed / 1000).toFixed(1)}s | ` +
      `spawn=${proof?.spawn_ok} steer=${proof?.steer_ok} ok=${proof?.ok} | ` +
      `agent=${proof?.agent_id} args=${JSON.stringify(proof?.args ?? [])}`,
  );
  console.log(`[proof] ${id}: detail=${proof?.detail ?? '-'}`);
  console.log(`[proof] ${id}: arquivo=${file} conteudo=${JSON.stringify(onDisk)}`);

  results.push({
    runtime: id,
    dir,
    http_status: response.status,
    elapsed_ms: elapsed,
    proof,
    file,
    file_content: onDisk,
    file_exists: onDisk !== null,
  });
}

const after = await call('GET', '/control/v1/agents', { token, timeoutMs: 30000 });
const afterById = new Map((after.body?.agents ?? []).map((agent) => [agent.id, agent]));
console.log('\n[proof] /agents depois:');
for (const id of ids) {
  const agent = afterById.get(id);
  console.log(
    `[proof]   ${id}: available=${agent?.available} execution_supported=${agent?.execution_supported} ` +
      `proof=${agent?.proof ? JSON.stringify(agent.proof) : '-'}`,
  );
}

const evidence = {
  measured_at: new Date().toISOString(),
  base_url: baseUrl,
  token: { length: token.length, sha256_prefix: sha256(token) },
  agents_before: Object.fromEntries([...beforeById.values()].map((a) => [a.id, { available: a.available, execution_supported: a.execution_supported }])),
  proofs: results,
  agents_after: Object.fromEntries([...afterById.values()].map((a) => [a.id, { available: a.available, execution_supported: a.execution_supported, proof: a.proof ?? null }])),
};
if (evidencePath) {
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  console.log(`[proof] evidência gravada em ${evidencePath}`);
}

const failed = results.filter((result) => !result.proof?.ok);
console.log(`\n[proof] resumo: ${results.length - failed.length}/${results.length} comprovados`);
if (failed.length > 0) {
  console.log(`[proof] sem prova: ${failed.map((result) => `${result.runtime} (${result.proof?.detail ?? result.transport_error})`).join('; ')}`);
  process.exit(1);
}
