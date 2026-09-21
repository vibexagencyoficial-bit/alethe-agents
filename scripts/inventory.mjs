#!/usr/bin/env node
// Gera o inventário das superfícies do Alethe (docs/alethe-integration-plan.md, Fase 1):
//   docs/inventory/tauri-commands.json  — comandos Tauri declarados vs registrados no invoke_handler
//   docs/inventory/http-endpoints.json  — endpoints do control plane declarados em control.rs
//   docs/inventory/mcp-tools.json       — tools MCP expostas pelo orquestrador
// Uso: node scripts/inventory.mjs
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcTauri = join(repoRoot, 'src-tauri', 'src');
const outDir = join(repoRoot, 'docs', 'inventory');

function listRustFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listRustFiles(full));
    else if (entry.endsWith('.rs')) out.push(full);
  }
  return out;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text[i] === '\n') line += 1;
  return line;
}

// 1. Comandos Tauri declarados: #[tauri::command] seguido de fn.
const declared = [];
for (const file of listRustFiles(srcTauri)) {
  const text = readFileSync(file, 'utf8');
  const re = /#\[tauri::command\]\s*(?:(?:\/\/\/[^\n]*|\/\/![^\n]*|#[^\n]*)\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    declared.push({
      name: match[1],
      file: relative(repoRoot, file).split(sep).join('/'),
      line: lineOf(text, match.index),
    });
  }
}

// 2. Comandos registrados no invoke_handler (a superfície realmente exposta ao frontend).
const libText = readFileSync(join(srcTauri, 'lib.rs'), 'utf8');
const handlerBlock = libText.match(/generate_handler!\[([\s\S]*?)\]\)/);
if (!handlerBlock) throw new Error('bloco generate_handler! não encontrado em lib.rs');
const registered = [...handlerBlock[1].matchAll(/([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)/g)]
  .map((match) => ({ module: match[1], name: match[2] }));

const declaredNames = new Set(declared.map((c) => c.name));
const registeredNames = new Set(registered.map((c) => c.name));
const tauriCommands = {
  generatedAt: new Date().toISOString(),
  counts: {
    declared: declared.length,
    registered: registered.length,
    registeredButNotDeclared: 0,
    declaredButNotRegistered: 0,
  },
  registeredButNotDeclared: registered.filter((c) => !declaredNames.has(c.name)),
  declaredButNotRegistered: declared.filter((c) => !registeredNames.has(c.name)).map((c) => `${c.name} (${c.file}:${c.line})`),
  declared,
};

// 3. Endpoints HTTP do control plane, na fonte autoritativa (arrays de capabilities em control.rs).
const controlText = readFileSync(join(srcTauri, 'control.rs'), 'utf8');
function endpointsOf(section) {
  const block = controlText.match(new RegExp(`"${section}":\\s*\\[([\\s\\S]*?)\\]`));
  if (!block) throw new Error(`seção "${section}" não encontrada em control.rs`);
  return [...block[1].matchAll(/"method":\s*"([A-Z]+)",\s*"path":\s*"([^"]+)"/g)]
    .map((match) => ({ method: match[1], path: match[2] }));
}
const httpEndpoints = {
  generatedAt: new Date().toISOString(),
  source: 'src-tauri/src/control.rs (capabilities)',
  counts: { public: 0, authenticated: 0 },
  publicEndpoints: endpointsOf('public_endpoints'),
  authenticatedEndpoints: endpointsOf('authenticated_endpoints'),
};
httpEndpoints.counts.public = httpEndpoints.publicEndpoints.length;
httpEndpoints.counts.authenticated = httpEndpoints.authenticatedEndpoints.length;

// 4. Tools MCP do orquestrador (fn tools() em orchestrator_core.rs).
const coreText = readFileSync(join(srcTauri, 'orchestrator_core.rs'), 'utf8');
const toolsStart = coreText.indexOf('pub fn tools()');
if (toolsStart < 0) throw new Error('fn tools() não encontrada em orchestrator_core.rs');
const toolsBody = coreText.slice(toolsStart, coreText.indexOf('\n}\n', toolsStart));
const mcpTools = {
  generatedAt: new Date().toISOString(),
  source: 'src-tauri/src/orchestrator_core.rs (fn tools)',
  counts: { tools: 0 },
  tools: [...toolsBody.matchAll(/"name":\s*"([A-Za-z0-9_]+)",\s*"description":\s*"((?:[^"\\]|\\.)*)"/g)]
    .map((match) => ({ name: match[1], description: match[2] })),
};
mcpTools.counts.tools = mcpTools.tools.length;

mkdirSync(outDir, { recursive: true });
for (const [name, payload] of [
  ['tauri-commands.json', tauriCommands],
  ['http-endpoints.json', httpEndpoints],
  ['mcp-tools.json', mcpTools],
]) {
  writeFileSync(join(outDir, name), `${JSON.stringify(payload, null, 2)}\n`);
}

console.log(`tauri: ${declared.length} declarados, ${registered.length} registrados, ` +
  `${tauriCommands.registeredButNotDeclared.length} sem declaração, ${tauriCommands.declaredButNotRegistered.length} sem registro`);
console.log(`http: ${httpEndpoints.counts.public} públicos, ${httpEndpoints.counts.authenticated} autenticados`);
console.log(`mcp: ${mcpTools.counts.tools} tools`);
