// Tier 1 decision logic — SPEC.md §8.2, §8.3, §9.1.
//
// Everything here is a pure function. The Service Worker in veil-guard-sw.js is
// deliberately thin: it does I/O and calls into this module, so that the rules
// that decide whether code runs can be tested without a browser, a Cache Storage,
// or an IndexedDB.

import {
  contentTypeMatches,
  requestKey,
  resolveEntry,
  trustRootId,
  verifyRotation,
} from './veilguard-verify.mjs';

/// SPEC §9.1: how far a client will walk a rotation chain in one session.
export const MAX_ROTATION_CHAIN = 8;

/// SPEC §8.2. Soft states still serve; hard states block everything in scope.
export const HARD_STATES = ['TAMPERED', 'ROLLBACK', 'UNTRUSTED_ROOT', 'UNSUPPORTED'];
export const SOFT_STATES = ['VALID', 'EXPIRED', 'NETWORK_FAIL'];

export function isHardFailure(state) {
  return HARD_STATES.includes(state);
}

/// The message class shown to a person. A network failure must never be dressed
/// up as an attack: conflating a CDN outage with tampering trains users to ignore
/// the one alert that matters.
export function presentationFor(state) {
  switch (state) {
    case 'VALID':
      return { ui: 'none', blocking: false };
    case 'EXPIRED':
      return { ui: 'notice', blocking: false, message: 'This site has not been re-signed recently.' };
    case 'NETWORK_FAIL':
      return { ui: 'retry', blocking: false, message: 'Could not reach the server.' };
    case 'UNSUPPORTED':
      return {
        ui: 'unsupported',
        blocking: true,
        message: 'This browser cannot check any of the signature algorithms this site uses.',
      };
    default:
      return { ui: 'security', blocking: true, message: 'The code served by this site does not match what its developers signed.' };
  }
}

// ------------------------------------------------------------------ scope
/// SPEC §8.3. A path is in scope when it matches an `include` prefix and no
/// `exclude` prefix. Prefixes are matched on path segments, so `/api` does not
/// swallow `/apiary.js`.
export function inScope(pathname, scope) {
  const include = scope?.include?.length ? scope.include : ['/'];
  const exclude = scope?.exclude ?? [];
  const matches = (prefix) =>
    prefix === '/' ? true : pathname === prefix || pathname.startsWith(prefix.replace(/\/$/, '') + '/');
  return include.some(matches) && !exclude.some(matches);
}

// ------------------------------------------------------------------ per request
/// Decide what to do with a request before it is made. SPEC §8.3.
///
/// `PASSTHROUGH` means veil-guard has nothing to say about this request — it is
/// cross-origin, or outside the declared scope. `BLOCK_UNMANIFESTED` is the
/// allowlist behaviour, and it is the default: a blocklist would be defeated by
/// choosing a filename that is not on it.
export function decideRequest({ url, origin, destination, manifestState, manifest }) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { outcome: 'PASSTHROUGH', reason: 'unparseable-url' };
  }

  if (parsed.origin !== origin) {
    return { outcome: 'PASSTHROUGH', reason: 'cross-origin' };
  }

  // The manifest and its signature are how the worker learns anything at all;
  // they cannot be subject to their own allowlist.
  if (parsed.pathname === '/veil-guard-manifest.json' || parsed.pathname === '/veil-guard-manifest.sig') {
    return { outcome: 'PASSTHROUGH', reason: 'control-plane' };
  }

  if (isHardFailure(manifestState)) {
    return { outcome: 'BLOCK_TAMPER', reason: `manifest-${manifestState}` };
  }

  // No manifest means nothing can be checked, and without one there is not even a
  // scope to consult. Passing the request through would serve unverified bytes,
  // which is the one thing this worker exists to prevent — so it fails closed.
  //
  // This is reported as a network failure rather than as tampering, because that
  // is what it almost always is: a worker that the browser restarted before it
  // could re-read the manifest, or an origin that is briefly unreachable.
  if (!manifest) {
    return { outcome: 'BLOCK_NO_MANIFEST', reason: 'manifest-unavailable' };
  }

  const key = requestKey(parsed.pathname);
  if (key === null) {
    // SPEC §7.1 rejects these before decoding; a URL shaped this way is an attempt
    // to make one path look like another.
    return { outcome: 'BLOCK_TAMPER', reason: 'illegal-path' };
  }

  if (!inScope(key, manifest.scope)) {
    return { outcome: 'PASSTHROUGH', reason: 'out-of-scope' };
  }

  // A navigation keeps its own redirect mode; only subresources get
  // `redirect: 'error'` (SPEC §7.2).
  const isNavigation = destination === 'document';

  const entry = resolveEntry(manifest, key, isNavigation);
  if (!entry) {
    // Subresources are an allowlist: anything not signed is refused.
    if (!isNavigation) return { outcome: 'BLOCK_UNMANIFESTED', reason: 'not-in-manifest', key };

    // Navigations are not. A server may map `/faq`, `/about/`, or any rewritten
    // route onto a document in ways a list of files cannot express, and blocking a
    // navigation on that guess replaces the site with a blank page. The document's
    // subresources are still fully covered, which is where executable code lives —
    // and the worker never controls the first navigation anyway, so treating an
    // unmatched one as fatal buys nothing it does not already lack.
    return { outcome: 'PASSTHROUGH', reason: 'navigation-not-manifested', key };
  }

  return { outcome: 'CHECK', entry, key, isNavigation };
}

/// Decide what to do with a response that has arrived. SPEC §8.3.
/// Decide what to do with a response that has arrived. SPEC §8.3.
///
/// `digestHex` and `byteLength` are omitted when the body has not been read yet —
/// the streaming path calls this before it has either, and again from
/// [`decideStreamedBody`] once the stream ends. Everything that can be judged from
/// the head alone is judged on the first call, so that a redirect or a wrong media
/// type is refused before a single byte reaches the page.
export function decideResponse({ entry, status, redirected, contentType, digestHex, byteLength }) {
  if (status === 206) {
    // A whole-file hash says nothing about a byte range. Media that needs range
    // requests belongs in scope.exclude (SPEC §7.3).
    return { outcome: 'PASSTHROUGH', reason: 'partial-content' };
  }
  if (redirected) {
    return { outcome: 'BLOCK_TAMPER', reason: 'redirected' };
  }
  if (status !== 200) {
    return { outcome: 'NETWORK_FAIL', reason: `http-${status}` };
  }
  if (contentType && !contentTypeMatches(entry.content_type, contentType)) {
    return { outcome: 'BLOCK_TAMPER', reason: 'content-type-mismatch' };
  }
  if (digestHex !== undefined && digestHex !== entry.sha256) {
    return { outcome: 'BLOCK_TAMPER', reason: 'hash-mismatch' };
  }
  if (byteLength !== undefined && byteLength !== entry.size) {
    return { outcome: 'BLOCK_TAMPER', reason: 'size-mismatch' };
  }
  if (digestHex === undefined || byteLength === undefined) {
    return { outcome: 'READ_BODY' };
  }
  return { outcome: 'SERVE_VERIFIED' };
}

/// The second half of the streaming verdict, once the body has been counted and
/// hashed. Split out so the two checks a stream can only make at the end are not
/// quietly skipped along with the ones it makes at the start.
export function decideStreamedBody({ entry, digestHex, byteLength }) {
  if (digestHex !== entry.sha256) {
    return { outcome: 'BLOCK_TAMPER', reason: 'hash-mismatch' };
  }
  if (byteLength !== entry.size) {
    return { outcome: 'BLOCK_TAMPER', reason: 'size-mismatch' };
  }
  return { outcome: 'SERVE_VERIFIED' };
}

// ------------------------------------------------------------------ pinning
/// Decide how the stored pin should change after a manifest verified.
///
/// Trust-on-first-use: with no pin, the trust root the worker was built with is
/// adopted and recorded. Afterwards the *pinned* root is authoritative — the root
/// baked into a freshly served worker cannot silently replace it, because that is
/// exactly what an attacker who can rewrite the worker would do. Moving the pin
/// requires a rotation statement signed by the pinned root.
export function pinTransition({ pin, manifestVersion, trustRootIdHex }) {
  if (!pin) {
    return {
      action: 'adopt',
      pin: { trustRootId: trustRootIdHex, version: manifestVersion, rotationVersion: 0 },
    };
  }
  if (pin.trustRootId !== trustRootIdHex) {
    return { action: 'reject', reason: 'trust-root-changed-without-rotation' };
  }
  if (manifestVersion < pin.version) {
    return { action: 'reject', reason: 'rollback' };
  }
  if (manifestVersion > pin.version) {
    return { action: 'advance', pin: { ...pin, version: manifestVersion } };
  }
  return { action: 'unchanged', pin };
}

/// Walk a rotation chain from the pinned root towards a target root.
///
/// `fetchStatement(index)` returns `{ payload, bundle }` or null when the chain
/// ends. The cap is not a formality: without it a hostile origin could serve an
/// endless chain and hang the worker on every navigation.
export async function applyRotationChain({ pin, pinnedRoot, fetchStatement, supported }) {
  let currentRoot = pinnedRoot;
  let currentPin = { ...pin };
  const applied = [];

  for (let i = 0; i < MAX_ROTATION_CHAIN; i++) {
    const next = await fetchStatement(i);
    if (!next) break;

    const verdict = await verifyRotation({
      payload: next.payload,
      bundle: next.bundle,
      pinned: currentRoot,
      pinnedRotationVersion: currentPin.rotationVersion ?? 0,
      supported,
    });
    if (verdict !== 'ACCEPT') {
      return { ok: false, reason: 'rotation-rejected', applied, root: currentRoot, pin: currentPin };
    }

    const statement = JSON.parse(new TextDecoder().decode(next.payload));
    const newId = await trustRootId(statement.to_trust_root);
    if (applied.includes(newId)) {
      return { ok: false, reason: 'rotation-cycle', applied, root: currentRoot, pin: currentPin };
    }

    currentRoot = statement.to_trust_root;
    currentPin = { ...currentPin, trustRootId: newId, rotationVersion: statement.version };
    applied.push(newId);
  }

  return { ok: true, root: currentRoot, pin: currentPin, applied };
}
