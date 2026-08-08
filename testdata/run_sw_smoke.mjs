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

const root = sandbox.self.VEIL_GUARD_TRUST_ROOT;
console.log(`handlers        : ${[...listeners.keys()].sort().join(', ')}`);
console.log(`trust root      : ${root.threshold}-of-${root.keys.length}, algs ${root.sigalgs.join('+')}`);
console.log(`bundle size     : ${(source.length / 1024).toFixed(1)} KiB`);
console.log('OK');
