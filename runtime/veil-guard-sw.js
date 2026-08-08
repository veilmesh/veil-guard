// veil-guard Tier 1 — Service Worker.
//
// This is the second line, not the boundary. It cannot see inline scripts (there
// is no fetch event for them), it does not control the first navigation, and a
// compromised origin can replace this file or clear it with `Clear-Site-Data`.
// What it does cover is what SRI cannot: dynamic `import()`, `fetch()`, and wasm
// chunks that no HTML tag ever names. See SPEC.md §1 and the README threat model.
//
// Built by `veil-guard runtime --out <dir>`, which inlines the two modules below
// and the trust root, producing one self-contained file. Loading the verification
// core with `importScripts` would mean executing unverified code to decide whether
// code is verified, so it is never done.

import {
  detectSupported,
  hex,
  sha256,
  trustRootId,
  verifyManifest,
} from './veilguard-verify.mjs';
import {
  applyRotationChain,
  decideRequest,
  decideResponse,
  isHardFailure,
  pinTransition,
  presentationFor,
} from './veilguard-policy.mjs';

// Replaced at build time with the trust root this build was signed against.
const BAKED_TRUST_ROOT = self.VEIL_GUARD_TRUST_ROOT ?? null;

const CACHE = 'veil-guard-v1';
const DB_NAME = 'veil-guard';
const DB_STORE = 'pin';
const MANIFEST_URL = '/veil-guard-manifest.json';
const SIG_URL = '/veil-guard-manifest.sig';
const ROTATION_URL = (i) => (i === 0 ? '/veil-guard-rotation.json' : `/veil-guard-rotation.${i}.json`);

let state = {
  manifestState: 'NETWORK_FAIL',
  manifest: null,
  root: null,
  pin: null,
  supported: null,
  checkedAt: 0,
};

// ------------------------------------------------------------------ storage
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(DB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function readPin() {
  try {
    const db = await idb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(DB_STORE, 'readonly').objectStore(DB_STORE).get('current');
      tx.onsuccess = () => resolve(tx.result ?? null);
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    return null;
  }
}

async function writePin(pin) {
  const db = await idb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readwrite').objectStore(DB_STORE).put(pin, 'current');
    tx.onsuccess = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

// ------------------------------------------------------------------ control plane
async function fetchControl(url) {
  // `cache: 'no-store'` on purpose: a stale manifest would make a fresh deploy look
  // like tampering, and a cached one could outlive a rotation.
  const res = await fetch(url, { cache: 'no-store', redirect: 'error' });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

// The control plane is mirrored into Cache Storage so that a worker the browser
// restarted can recover without the network. The mirror is never trusted: what
// comes back out of it goes through the same signature check as what comes off
// the wire, so a poisoned cache buys an attacker nothing.
const CONTROL_MANIFEST = 'https://veil-guard.invalid/control/manifest';
const CONTROL_SIG = 'https://veil-guard.invalid/control/sig';

async function saveControl(payload, bundle) {
  try {
    const cache = await caches.open(CACHE);
    await cache.put(CONTROL_MANIFEST, new Response(payload));
    await cache.put(CONTROL_SIG, new Response(bundle));
  } catch {
    // Storage pressure or a private window: recovery just falls back to network.
  }
}

async function loadControl() {
  try {
    const cache = await caches.open(CACHE);
    const [m, s] = await Promise.all([cache.match(CONTROL_MANIFEST), cache.match(CONTROL_SIG)]);
    if (!m || !s) return null;
    return [new Uint8Array(await m.arrayBuffer()), new Uint8Array(await s.arrayBuffer())];
  } catch {
    return null;
  }
}

async function refresh() {
  state.supported ??= await detectSupported();

  let payload;
  let bundle;
  let fromCache = false;
  try {
    [payload, bundle] = await Promise.all([fetchControl(MANIFEST_URL), fetchControl(SIG_URL)]);
  } catch (e) {
    // Could not reach the control plane. This is an outage, not an attack — but a
    // restarted worker has no in-memory manifest either, so try the mirror before
    // giving up, and re-verify whatever it returns.
    const cached = await loadControl();
    if (!cached) {
      state.manifestState = state.manifest ? state.manifestState : 'NETWORK_FAIL';
      broadcast({ type: 'veil-guard:state', state: state.manifestState, detail: String(e) });
      return state.manifestState;
    }
    [payload, bundle] = cached;
    fromCache = true;
  }

  let pin = await readPin();
  let root = pin?.trustRoot ?? BAKED_TRUST_ROOT;
  if (!root) {
    state.manifestState = 'UNTRUSTED_ROOT';
    broadcast({ type: 'veil-guard:state', state: state.manifestState, detail: 'no trust root' });
    return state.manifestState;
  }

  // A worker whose baked-in root differs from the pin is either a legitimate key
  // rotation or an attacker swapping the root. Only a rotation statement signed by
  // the pinned root can tell those apart.
  if (pin && BAKED_TRUST_ROOT && pin.trustRootId !== (await safeRootId(BAKED_TRUST_ROOT))) {
    const walked = await applyRotationChain({
      pin,
      pinnedRoot: pin.trustRoot,
      supported: state.supported,
      fetchStatement: async (i) => {
        try {
          const [p, b] = await Promise.all([
            fetchControl(ROTATION_URL(i)),
            fetchControl(ROTATION_URL(i).replace(/\.json$/, '.sig')),
          ]);
          return { payload: p, bundle: b };
        } catch {
          return null;
        }
      },
    });
    if (walked.ok && walked.applied.length) {
      root = walked.root;
      pin = { ...walked.pin, trustRoot: walked.root };
      await writePin(pin);
    }
  }

  const verdict = await verifyManifest({
    payload,
    bundle,
    pinned: root,
    pinnedVersion: pin?.version ?? 0,
    supported: state.supported,
  });

  if (isHardFailure(verdict)) {
    state.manifestState = verdict;
    state.manifest = null;
    broadcast({ type: 'veil-guard:state', state: verdict, ...presentationFor(verdict) });
    return verdict;
  }

  const manifest = JSON.parse(new TextDecoder().decode(payload));
  const transition = pinTransition({
    pin,
    manifestVersion: manifest.version,
    trustRootIdHex: manifest.trust_root_id,
  });
  if (transition.action === 'reject') {
    state.manifestState = transition.reason === 'rollback' ? 'ROLLBACK' : 'UNTRUSTED_ROOT';
    state.manifest = null;
    broadcast({ type: 'veil-guard:state', state: state.manifestState, ...presentationFor(state.manifestState) });
    return state.manifestState;
  }
  if (transition.action !== 'unchanged') {
    await writePin({ ...transition.pin, trustRoot: root });
  }

  if (!fromCache) await saveControl(payload, bundle);

  state = {
    ...state,
    manifestState: verdict,
    manifest,
    root,
    pin: transition.pin ?? pin,
    checkedAt: Date.now(),
  };
  broadcast({ type: 'veil-guard:state', state: verdict, ...presentationFor(verdict) });
  return verdict;
}

// A Service Worker is terminated whenever the browser feels like it, and its
// module state goes with it. `install` and `activate` do not fire again on
// restart, so without this every request between a restart and the next lifecycle
// event would find no manifest. Single-flight, so a burst of requests waking a
// cold worker produces one refresh rather than dozens.
let readying = null;

function ensureReady() {
  if (state.manifest && !isHardFailure(state.manifestState)) return Promise.resolve();
  readying ??= refresh().finally(() => {
    readying = null;
  });
  return readying;
}

async function safeRootId(root) {
  try {
    return await trustRootId(root);
  } catch {
    return null;
  }
}

function broadcast(message) {
  self.clients.matchAll({ includeUncontrolled: true }).then((clients) => {
    for (const c of clients) c.postMessage(message);
  });
}

// ------------------------------------------------------------------ serving
function blockedResponse(reason, key) {
  broadcast({ type: 'veil-guard:blocked', reason, subject: key ?? null, ...presentationFor('TAMPERED') });
  // An opaque error rather than a body: whatever the page expected here, it must
  // not receive something that could be parsed or executed.
  return new Response(null, { status: 526, statusText: 'veil-guard integrity failure' });
}

async function cacheKeyFor(entry) {
  return new Request(`https://veil-guard.invalid/${entry.sha256}`);
}

function unavailableResponse(reason) {
  broadcast({ type: 'veil-guard:network', reason, ...presentationFor('NETWORK_FAIL') });
  return new Response(null, { status: 523, statusText: 'veil-guard cannot verify right now' });
}

async function handle(request) {
  // Must come first: on a cold worker there is no manifest yet, and deciding
  // without one used to mean passing the request straight through.
  await ensureReady();

  const decision = decideRequest({
    url: request.url,
    origin: self.location.origin,
    destination: request.destination,
    manifestState: state.manifestState,
    manifest: state.manifest,
  });

  if (decision.outcome === 'PASSTHROUGH') return fetch(request);
  if (decision.outcome === 'BLOCK_NO_MANIFEST') return unavailableResponse(decision.reason);
  if (decision.outcome === 'BLOCK_UNMANIFESTED' || decision.outcome === 'BLOCK_TAMPER') {
    return blockedResponse(decision.reason, decision.key);
  }

  const { entry, isNavigation } = decision;
  const cache = await caches.open(CACHE);
  const cacheKey = await cacheKeyFor(entry);

  // Cache Storage is keyed by digest, not by URL, so a hit is already proof the
  // bytes were verified once. Eviction under storage pressure is ordinary browser
  // behaviour and means "fetch and verify again", never "tampering".
  const hit = await cache.match(cacheKey);
  if (hit) return hit;

  // SPEC §7.2: a subresource must not follow a redirect, or a response for one
  // manifest entry could be validated against another entry's hash. Navigations
  // keep their own mode — forcing `error` there breaks locale and trailing-slash
  // redirects. The mode cannot be changed on an existing Request, so a new one is
  // constructed.
  let response;
  try {
    response = isNavigation
      ? await fetch(request)
      : await fetch(new Request(request.url, { redirect: 'error', credentials: request.credentials }));
  } catch (e) {
    broadcast({ type: 'veil-guard:network', subject: entry.path, ...presentationFor('NETWORK_FAIL') });
    return new Response(null, { status: 523, statusText: 'veil-guard could not reach origin' });
  }

  if (response.status === 206) return response;

  const bytes = new Uint8Array(await response.clone().arrayBuffer());
  const verdict = decideResponse({
    entry,
    status: response.status,
    redirected: response.redirected,
    contentType: response.headers.get('content-type'),
    digestHex: hex(await sha256(bytes)),
    byteLength: bytes.byteLength,
  });

  if (verdict.outcome === 'BLOCK_TAMPER') return blockedResponse(verdict.reason, entry.path);
  if (verdict.outcome === 'NETWORK_FAIL') {
    broadcast({ type: 'veil-guard:network', subject: entry.path, ...presentationFor('NETWORK_FAIL') });
    return response;
  }
  if (verdict.outcome === 'PASSTHROUGH') return response;

  await cache.put(cacheKey, response.clone());
  return response;
}

// ------------------------------------------------------------------ lifecycle
self.addEventListener('install', (event) => {
  event.waitUntil(refresh().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((n) => n.startsWith('veil-guard-') && n !== CACHE).map((n) => caches.delete(n)));
      await self.clients.claim();
      await refresh();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(handle(event.request));
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'veil-guard:status') {
    event.source?.postMessage({
      type: 'veil-guard:state',
      state: state.manifestState,
      version: state.manifest?.version ?? null,
      assets: state.manifest?.assets.length ?? 0,
      checkedAt: state.checkedAt,
      ...presentationFor(state.manifestState),
    });
  }
  if (event.data?.type === 'veil-guard:refresh') {
    event.waitUntil?.(refresh());
  }
});
