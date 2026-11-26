#!/usr/bin/env node
// What a blocked request looks like, end to end through the bundled worker
// (issue #1003).
//
//   node testdata/run_sw_navigation.mjs <bundled-sw.js> <signed-dist-v1> <signed-dist-v2>
//
// Both dists are signed by the same trust root the worker was built with; v2 has a
// different index.html. The worker runs in a stubbed worker scope whose `fetch`
// serves files from disk, so every check below goes through the real `handle`:
//
//   1. a tampered navigation gets a self-contained HTML page (status 526, no
//      script, the path and the reason); a tampered subresource gets the opaque
//      empty 526;
//   2. a navigation whose HTML is newer than the manifest the worker holds is
//      served once the manifest is read again (one re-read, `no-store`);
//   3. a mismatch that survives the re-read is still blocked, after exactly one
//      extra manifest fetch.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createContext, runInContext } from 'node:vm';

const [target, v1, v2] = process.argv.slice(2);
if (!target || !v1 || !v2) {
  console.error('usage: run_sw_navigation.mjs <bundled-sw.js> <signed-dist-v1> <signed-dist-v2>');
  process.exit(2);
}
const source = readFileSync(target, 'utf8');
const ORIGIN = 'https://app.example';

let pass = 0;
let fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) {
    pass++;
    console.log(`  ok   ${name}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`);
  }
};

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
const typeOf = (path) => TYPES[path.slice(path.lastIndexOf('.'))] ?? 'application/octet-stream';

/// A worker in a fresh scope. `manifests` — which dist each successive manifest
/// fetch is served from (the last one repeats); `files(path)` — the bytes of a
/// file, or undefined for a 404.
function worker({ manifests, files }) {
  const listeners = new Map();
  const counts = { manifest: 0 };
  const caches = new Map();
  const store = new Map();
  const later = (fn) => setTimeout(fn, 0);
  const respond = (path, bytes) => new Response(bytes, { status: 200, headers: { 'content-type': typeOf(path) } });

  const sandbox = {
    self: {
      addEventListener: (type, fn) => {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push(fn);
      },
      location: { origin: ORIGIN },
      skipWaiting: async () => {},
      clients: { claim: async () => {}, matchAll: async () => (process.env.VG_DEBUG ? [{ postMessage: (m) => console.error('posted', JSON.stringify(m)) }] : []) },
    },
    crypto: globalThis.crypto,
    console,
    TextDecoder,
    TextEncoder,
    TransformStream,
    URL,
    Uint8Array,
    DataView,
    Response,
    Request,
    Headers,
    WebAssembly,
    fetch: async (input) => {
      const path = new URL(typeof input === 'string' ? input : input.url, ORIGIN).pathname;
      if (path === '/veil-guard-manifest.json' || path === '/veil-guard-manifest.sig') {
        const n = path.endsWith('.json') ? counts.manifest++ : Math.max(counts.manifest - 1, 0);
        const dir = manifests[Math.min(n, manifests.length - 1)];
        return respond(path, readFileSync(join(dir, path)));
      }
      const bytes = files(path);
      return bytes === undefined ? new Response(null, { status: 404 }) : respond(path, bytes);
    },
    caches: {
      open: async (name) => {
        if (!caches.has(name)) caches.set(name, new Map());
        const c = caches.get(name);
        const key = (k) => (typeof k === 'string' ? k : k.url);
        return {
          match: async (k) => c.get(key(k))?.clone(),
          put: async (k, r) => void c.set(key(k), r),
        };
      },
      keys: async () => [...caches.keys()],
      delete: async (n) => caches.delete(n),
    },
    // Enough of IndexedDB for the pin: one store, kept in memory.
    indexedDB: {
      open: () => {
        const req = {};
        later(() => {
          req.result = {
            createObjectStore: () => {},
            transaction: () => ({
              objectStore: () => ({
                get: (k) => {
                  const r = {};
                  later(() => {
                    r.result = store.get(k);
                    r.onsuccess?.();
                  });
                  return r;
                },
                put: (v, k) => {
                  const r = {};
                  later(() => {
                    store.set(k, v);
                    r.onsuccess?.();
                  });
                  return r;
                },
              }),
            }),
          };
          req.onsuccess?.();
        });
        return req;
      },
    },
    Date,
    Promise,
    JSON,
    Math,
    Number,
    Error,
    TypeError,
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
    atob,
    btoa,
  };
  sandbox.globalThis = sandbox;
  sandbox.self.globalThis = sandbox;
  runInContext(source, createContext(sandbox), { filename: target });

  const fetchEvent = async (path, destination) => {
    let answer;
    const request =
      destination === 'document'
        ? { url: ORIGIN + path, method: 'GET', destination, mode: 'navigate', credentials: 'include' }
        : { url: ORIGIN + path, method: 'GET', destination, mode: 'cors', credentials: 'same-origin' };
    for (const fn of listeners.get('fetch')) fn({ request, respondWith: (p) => (answer = p) });
    return answer;
  };
  return { fetchEvent, counts };
}

const fileOf = (dir) => (path) => {
  try {
    return readFileSync(join(dir, path === '/' ? 'index.html' : path));
  } catch {
    return undefined;
  }
};

console.log('\ntampered: a page for a navigation, nothing for a subresource');
{
  const injected = (path) => {
    const bytes = fileOf(v1)(path);
    if (path === '/index.html') return Buffer.from(String(bytes).replace('</head>', '<script src="/beacon.js"></script></head>'));
    if (path === '/assets/app.js') return Buffer.from('export const x = 666;\n');
    return bytes;
  };
  const w = worker({ manifests: [v1], files: injected });
  const page = await w.fetchEvent('/index.html', 'document');
  const body = page.body ? await page.text() : '';
  check('the navigation is answered 526', page.status === 526, `got ${page.status}`);
  check('with an HTML page', (page.headers.get('content-type') ?? '').startsWith('text/html'), page.headers.get('content-type'));
  check('that says what happened', body.includes('This page was blocked') && body.includes('does not match what its developers signed'));
  check('names the path and the reason', body.includes('/index.html') && body.includes('hash-mismatch'));
  check('offers to try again', body.includes('Try again'));
  check('and carries no script at all', !/<script/i.test(body));
  check('nor loads anything', !/<(link|img|iframe|object|embed)\b/i.test(body) && !/url\(/i.test(body));
  check("its CSP forbids scripts", /default-src 'none'/.test(page.headers.get('content-security-policy') ?? ''));
  check('one extra manifest read before blocking', w.counts.manifest === 2, `manifest fetched ${w.counts.manifest} times`);

  const script = await w.fetchEvent('/assets/app.js', 'script');
  check('the subresource is answered 526', script.status === 526, `got ${script.status}`);
  check('with an empty body', script.body === null || (await script.text()) === '');
  check('the subresource does not re-read the manifest', w.counts.manifest === 2, `manifest fetched ${w.counts.manifest} times`);
}

console.log('\na deploy racing the manifest: the HTML is newer than the manifest held');
{
  const w = worker({ manifests: [v1, v2], files: fileOf(v2) });
  const page = await w.fetchEvent('/index.html', 'document');
  const body = page.body ? await page.text() : '';
  check('the page is served after one manifest re-read', page.status === 200, `got ${page.status}`);
  check('with the new bytes', body === String(fileOf(v2)('/index.html')));
  check('the manifest was read exactly twice', w.counts.manifest === 2, `manifest fetched ${w.counts.manifest} times`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
