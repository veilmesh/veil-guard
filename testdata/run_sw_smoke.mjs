#!/usr/bin/env node
// Load a bundled Service Worker in a stubbed worker global scope.
//
//   node testdata/run_sw_smoke.mjs <path-to-bundled-sw.js>
//
// `node --check` only proves the file parses. This proves it *evaluates*: that the
// concatenation left every symbol resolvable, that nothing at top level needs a
// browser API that is missing, and that the lifecycle handlers actually register.
// A bundling mistake that silently dropped the fetch handler would produce a
// worker that installs cleanly and verifies nothing at all.

import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';
import { createHash } from 'node:crypto';

const target = process.argv[2];
if (!target) {
  console.error('usage: run_sw_smoke.mjs <bundled-sw.js>');
  process.exit(2);
}

const listeners = new Map();
const posted = [];

const self = {
  addEventListener: (type, fn) => {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(fn);
  },
  location: { origin: 'https://app.example' },
  skipWaiting: async () => {},
  clients: {
    claim: async () => {},
    matchAll: async () => [{ postMessage: (m) => posted.push(m) }],
  },
};

const sandbox = {
  self,
  crypto: globalThis.crypto,
  console,
  TextDecoder,
  TextEncoder,
  URL,
  Uint8Array,
  DataView,
  Response,
  Request,
  Headers,
  fetch: async () => {
    throw new Error('network disabled in smoke test');
  },
  caches: { open: async () => ({ match: async () => undefined, put: async () => {} }), keys: async () => [], delete: async () => true },
  indexedDB: { open: () => ({ set onsuccess(_) {}, set onerror(_) {}, set onupgradeneeded(_) {} }) },
  Date,
  Promise,
  JSON,
  Math,
  Number,
  Error,
  Set,
  Map,
  Object,
  Array,
  String,
  Boolean,
  RegExp,
  isNaN,
  parseInt,
  setTimeout,
};
sandbox.globalThis = sandbox;
sandbox.self.globalThis = sandbox;

const source = readFileSync(target, 'utf8');

try {
  runInContext(source, createContext(sandbox), { filename: target });
} catch (e) {
  console.error(`FAIL: bundled worker threw while evaluating: ${e.message}`);
  process.exit(1);
}

const required = ['install', 'activate', 'fetch', 'message'];
const missing = required.filter((t) => !listeners.has(t));
if (missing.length) {
  console.error(`FAIL: no handler registered for: ${missing.join(', ')}`);
  process.exit(1);
}

if (!sandbox.self.VEIL_GUARD_TRUST_ROOT) {
  console.error('FAIL: the bundle carries no baked-in trust root');
  process.exit(1);
}

// The streaming verifier is the one part of the worker whose failure is silent —
// a wrong digest, no exception — so check that what came out of the bundler is a
// Wasm module the engine will accept, and that it still computes SHA-256. The
// constant is a 90-line string concatenation, which is exactly the shape a
// bundler mangles, and it once shipped corrupt.
const b64Match = source.match(/WASM_SHA256_B64\s*=\s*((?:\s*'[^']*'\s*\+?)+)/);
if (!b64Match) {
  console.error('FAIL: the bundle carries no embedded Wasm hasher');
  process.exit(1);
}
const b64 = [...b64Match[1].matchAll(/'([^']*)'/g)].map((m) => m[1]).join('');
const wasmBytes = Buffer.from(b64, 'base64');

let hasherReport;
try {
  const { instance } = await WebAssembly.instantiate(wasmBytes);
  const ex = instance.exports;
  for (const fn of ['hasher_size', 'hasher_init', 'hasher_update', 'hasher_finalize', 'hasher_heap_base']) {
    if (typeof ex[fn] !== 'function') throw new Error(`export ${fn} is missing`);
  }

  // One end-to-end digest through the module's own ABI, over a chunk large
  // enough to have crossed the shadow stack under the first implementation.
  const base = ex.hasher_heap_base();
  const state = base;
  const out = base + 128;
  const data = base + 160;
  const payload = Buffer.alloc(200_000, 0x5a);
  const need = data + payload.length;
  if (need > ex.memory.buffer.byteLength) {
    ex.memory.grow(Math.ceil((need - ex.memory.buffer.byteLength) / 65536));
  }
  new Uint8Array(ex.memory.buffer).set(payload, data);
  ex.hasher_init(state);
  ex.hasher_update(state, data, payload.length);
  ex.hasher_finalize(state, out);
  const got = Buffer.from(new Uint8Array(ex.memory.buffer, out, 32)).toString('hex');
  const want = createHash('sha256').update(payload).digest('hex');
  if (got !== want) throw new Error(`digest mismatch:\n  got  ${got}\n  want ${want}`);
  hasherReport = `${wasmBytes.length} bytes, digest verified`;
} catch (e) {
  console.error(`FAIL: embedded Wasm hasher is unusable: ${e.message}`);
  process.exit(1);
}

const root = sandbox.self.VEIL_GUARD_TRUST_ROOT;
console.log(`handlers        : ${[...listeners.keys()].sort().join(', ')}`);
console.log(`trust root      : ${root.threshold}-of-${root.keys.length}, algs ${root.sigalgs.join('+')}`);
console.log(`wasm hasher     : ${hasherReport}`);
console.log(`bundle size     : ${(source.length / 1024).toFixed(1)} KiB`);
console.log('OK');
