// Reference JavaScript implementation of the veil-guard verification algorithm.
//
// SPEC.md §5 (signature bundle), §7.1 (request keys), §8.1 (verification) and
// §9.1 (rotation). Written against the plain WebCrypto surface a Service Worker
// has: no Node built-ins, no dependencies, no DOM. The Tier 1 runtime is derived
// from this module directly, and `tests/cross_language.rs` checks that it agrees
// with the Rust implementation on real CLI output.

const subtle = globalThis.crypto.subtle;

export const PREFIX = {
  manifest: te('veil-guard/manifest/v1\0'),
  rotation: te('veil-guard/rotation/v1\0'),
  revocation: te('veil-guard/revocation/v1\0'),
  keyid: te('veil-guard/keyid/v1\0'),
  trustroot: te('veil-guard/trustroot/v1\0'),
};

const ALG_ID = { 0x01: 'ed25519', 0x02: 'p256' };
export const ALL_ALGS = new Set(['ed25519', 'p256']);
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function te(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
export const hex = (b) =>
  [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

export function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export const sha256 = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
export const sha384 = async (b) => new Uint8Array(await subtle.digest('SHA-384', b));

/// Probe which algorithms this engine can actually verify. SPEC §8.1 accommodates
/// an engine that implements only one of them.
export async function detectSupported() {
  const out = new Set();
  for (const [alg, params] of [
    ['ed25519', { name: 'Ed25519' }],
    ['p256', { name: 'ECDSA', namedCurve: 'P-256' }],
  ]) {
    try {
      await subtle.importKey('raw', new Uint8Array(alg === 'ed25519' ? 32 : 65), params, false, [
        'verify',
      ]);
      out.add(alg);
    } catch {
      // An all-zero key is not importable for P-256, so treat a *format* rejection
      // as support and only an unknown-algorithm rejection as absence.
      try {
        await subtle.importKey('jwk', {}, params, false, ['verify']);
        out.add(alg);
      } catch (e) {
        if (e?.name !== 'NotSupportedError') out.add(alg);
      }
    }
  }
  return out;
}

export async function verifySig(alg, pubRaw, sig, data) {
  try {
    if (alg === 'ed25519') {
      const k = await subtle.importKey('raw', pubRaw, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, k, sig, data);
    }
    if (alg === 'p256') {
      // SPEC §2.1: 65-byte uncompressed SEC1 in, raw r||s signature in.
      const k = await subtle.importKey(
        'raw',
        pubRaw,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, data);
    }
  } catch {
    return false;
  }
  return false;
}

// ------------------------------------------------------------------ SPEC §5
export class BundleError extends Error {}

export function parseBundle(bytes) {
  if (bytes.length < 10) throw new BundleError('short header');
  if (String.fromCharCode(...bytes.subarray(0, 6)) !== 'VGSIG1') throw new BundleError('bad magic');
  if (bytes[6] !== 0x01) throw new BundleError('bad format version');
  if (bytes[7] !== 0x00) throw new BundleError('reserved byte set');

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = dv.getUint16(8, true);
  if (count < 1 || count > 64) throw new BundleError('entry_count out of range');

  const entries = [];
  let off = 10;
  for (let i = 0; i < count; i++) {
    if (off + 12 > bytes.length) throw new BundleError('truncated entry header');
    const keyId = bytes.subarray(off, off + 8);
    const algId = bytes[off + 8];
    if (bytes[off + 9] !== 0x00) throw new BundleError('reserved byte set in entry');
    const sigLen = dv.getUint16(off + 10, true);
    const alg = ALG_ID[algId];
    if (alg !== undefined && sigLen !== 64) throw new BundleError('bad sig_len for known alg');
    if (sigLen > 128) throw new BundleError('sig_len too large');
    if (off + 12 + sigLen > bytes.length) throw new BundleError('truncated signature');
    entries.push({ keyId, algId, alg, sig: bytes.subarray(off + 12, off + 12 + sigLen) });
    off += 12 + sigLen;
  }
  if (off !== bytes.length) throw new BundleError('trailing bytes');

  for (let i = 1; i < entries.length; i++) {
    const a = entries[i - 1];
    const b = entries[i];
    const c = compareBytes(a.keyId, b.keyId);
    if (c > 0 || (c === 0 && a.algId > b.algId)) throw new BundleError('entries not sorted');
    if (c === 0 && a.algId === b.algId) throw new BundleError('duplicate (key_id, alg_id)');
  }
  return entries;
}

// ------------------------------------------------------------------ SPEC §4
export async function keyId(edPubHex, p256PubHex) {
  const d = await sha256(cat(PREFIX.keyid, unhex(edPubHex), unhex(p256PubHex)));
  return hex(d.subarray(0, 8));
}

export async function trustRootId(root) {
  const mask =
    (root.sigalgs.includes('ed25519') ? 1 : 0) | (root.sigalgs.includes('p256') ? 2 : 0);
  const parts = [Uint8Array.from([root.threshold, root.keys.length, mask])];
  for (const k of root.keys) parts.push(unhex(k.key_id), unhex(k.ed25519), unhex(k.p256));
  return hex(await sha256(cat(PREFIX.trustroot, cat(...parts))));
}

export function trustRootValid(root) {
  if (!root || !Array.isArray(root.keys) || !Array.isArray(root.sigalgs)) return false;
  if (root.keys.length < 1 || root.keys.length > 16) return false;
  if (!(root.threshold >= 1 && root.threshold <= root.keys.length)) return false;
  if (root.sigalgs.length === 0) return false;
  for (let i = 1; i < root.sigalgs.length; i++) {
    if (root.sigalgs[i - 1] >= root.sigalgs[i]) return false;
  }
  for (let i = 1; i < root.keys.length; i++) {
    if (compareBytes(unhex(root.keys[i - 1].key_id), unhex(root.keys[i].key_id)) >= 0) return false;
  }
  return true;
}

// ------------------------------------------------------------------ SPEC §8.1
export async function checkThreshold(payload, entries, pinned, prefix, supported = ALL_ALGS) {
  const active = pinned.sigalgs.filter((a) => supported.has(a));
  if (active.length === 0) return { state: 'UNSUPPORTED', qualifying: 0 };

  const data = cat(prefix, payload);
  let qualifying = 0;

  for (const k of pinned.keys) {
    const kid = unhex(k.key_id);
    const present = [];
    for (const alg of active) {
      const e = entries.find((x) => eq(x.keyId, kid) && x.alg === alg);
      if (!e) continue;
      const pub = alg === 'ed25519' ? unhex(k.ed25519) : unhex(k.p256);
      // A present signature that fails is fatal. This is the downgrade defense:
      // holding one algorithm's key does not let an attacker drop the other and
      // still have this signer count.
      if (!(await verifySig(alg, pub, e.sig, data))) return { state: 'TAMPERED', qualifying };
      present.push(alg);
    }
    if (present.length === active.length) qualifying++;
  }
  return { state: null, qualifying };
}

export async function verifyManifest({
  payload,
  bundle,
  pinned,
  pinnedVersion = 0,
  now = Math.floor(Date.now() / 1000),
  supported = ALL_ALGS,
}) {
  if (!trustRootValid(pinned)) return 'UNTRUSTED_ROOT';

  let entries;
  try {
    entries = parseBundle(bundle);
  } catch {
    return 'TAMPERED';
  }

  const t = await checkThreshold(payload, entries, pinned, PREFIX.manifest, supported);
  if (t.state) return t.state;
  if (t.qualifying < pinned.threshold) return 'UNTRUSTED_ROOT';

  // Only now is it safe to look at the contents.
  let m;
  try {
    m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
  } catch {
    return 'TAMPERED';
  }

  if (m.spec !== 'veil-guard/1') return 'TAMPERED';
  if ((await trustRootId(m.trust_root)) !== m.trust_root_id) return 'TAMPERED';
  if (m.trust_root_id !== (await trustRootId(pinned))) return 'UNTRUSTED_ROOT';
  if (JSON.stringify(m.sigalgs) !== JSON.stringify(m.trust_root.sigalgs)) return 'TAMPERED';
  if (!Number.isSafeInteger(m.version) || !Number.isSafeInteger(m.not_after)) return 'TAMPERED';
  if (m.not_after <= m.version) return 'TAMPERED';

  for (let i = 0; i < m.assets.length; i++) {
    const a = m.assets[i];
    if (!Number.isSafeInteger(a.size) || a.size > MAX_SAFE) return 'TAMPERED';
    if (a.path.normalize('NFC') !== a.path) return 'TAMPERED';
    if (requestKey(a.path) !== a.path) return 'TAMPERED';
    if (i > 0 && !(m.assets[i - 1].path < a.path)) return 'TAMPERED';
  }

  if (m.version < pinnedVersion) return 'ROLLBACK';
  if (now > m.not_after) return 'EXPIRED';
  return 'VALID';
}

// ------------------------------------------------------------------ SPEC §9.1
export async function verifyRotation({
  payload,
  bundle,
  pinned,
  pinnedRotationVersion = 0,
  supported = ALL_ALGS,
}) {
  if (!trustRootValid(pinned)) return 'REJECT';

  let entries;
  try {
    entries = parseBundle(bundle);
  } catch {
    return 'REJECT';
  }

  const t = await checkThreshold(payload, entries, pinned, PREFIX.rotation, supported);
  if (t.state || t.qualifying < pinned.threshold) return 'REJECT';

  let r;
  try {
    r = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload));
  } catch {
    return 'REJECT';
  }
  if (r.spec !== 'veil-guard/rotation/1') return 'REJECT';
  if (r.from_trust_root_id !== (await trustRootId(pinned))) return 'REJECT';
  // Strictly greater — this is what stops a replayed rotation walking the pin back.
  if (!(r.version > pinnedRotationVersion)) return 'REJECT';
  if (!trustRootValid(r.to_trust_root)) return 'REJECT';
  return 'ACCEPT';
}

// ------------------------------------------------------------------ SPEC §7.1
export function requestKey(rawPathname) {
  // Rejected before decoding: decoding these would manufacture path structure that
  // was not in the URL the browser actually requested.
  if (/%2f|%5c|%2e%2e|%00/i.test(rawPathname)) return null;
  let p;
  try {
    p = decodeURIComponent(rawPathname);
  } catch {
    return null;
  }
  p = p.normalize('NFC');
  if (p.includes('\\') || p.includes('//') || p.includes('\0')) return null;
  if (!p.startsWith('/')) return null;
  // A trailing slash is a directory-style URL — `/` and `/blog/` are ordinary,
  // legal paths that every static site serves. Only an *interior* empty component
  // is illegal, and `//` above already rejects that.
  const parts = p.split('/');
  for (let i = 1; i < parts.length; i++) {
    if (parts[i] === '.' || parts[i] === '..') return null;
    if (parts[i] === '' && i !== parts.length - 1) return null;
  }
  return p;
}

/// Resolve a request key to the manifest entry that serves it.
///
/// A directory-style URL is served from its index document by essentially every
/// static host, and the manifest lists files, so `/blog/` has to be looked up as
/// `/blog/index.html`. Without this the worker rejects a site's own home page.
/// SPEC §7.1.1. `isNavigation` gates the `.html` fallback, which is itself gated on
/// the signer having set `scope.html_extension` — a subresource never gets it, since
/// a `<script src="/faq">` that silently resolved to `/faq.html` would be the worker
/// inventing a mapping the server never agreed to.
export function resolveEntry(manifest, key, isNavigation = false) {
  const direct = manifest.assets.find((a) => a.path === key);
  if (direct) return direct;
  if (key.endsWith('/')) {
    return manifest.assets.find((a) => a.path === key + 'index.html') ?? null;
  }
  if (isNavigation && manifest.scope?.html_extension === true) {
    return manifest.assets.find((a) => a.path === key + '.html') ?? null;
  }
  return null;
}

/// SPEC §6.4 content-type equivalence classes.
const CT_CLASSES = [
  [
    'text/javascript',
    'application/javascript',
    'application/x-javascript',
    'text/ecmascript',
    'application/ecmascript',
  ],
  ['application/json', 'text/json'],
  ['application/xml', 'text/xml'],
  ['application/yaml', 'text/yaml', 'application/x-yaml', 'text/x-yaml'],
];

export function contentTypeMatches(expected, actual) {
  const essence = (s) => (s ?? '').split(';')[0].trim().toLowerCase();
  const e = essence(expected);
  const a = essence(actual);
  if (e === a) return true;
  return CT_CLASSES.some((c) => c.includes(e) && c.includes(a));
}

// ── Wasm SHA-256 hasher ──────────────────────────────────────────────────────
//
// A no_std, no_alloc Rust SHA-256 implementation compiled to Wasm and embedded
// here as Base64. JS controls the allocations using a simple bump allocator over
// a shared scratch buffer; the Rust side is fully stateless.
//
// Build:
//   cd wasm-hasher
//   cargo build --target wasm32-unknown-unknown --release
//   base64 -i target/wasm32-unknown-unknown/release/veil_guard_wasm_hasher.wasm
// Then paste the output as WASM_SHA256_B64 below.
//
// CI refreshes this constant automatically via scripts/update-wasm-hasher.sh.

// @generated — do not edit by hand
const WASM_SHA256_B64 =
  'AGFzbQEAAAABJgdgAn9/AGADf39/AGAEf39/fwBgAAF/YAF/AGAAAGAFf39/f38AAxEQAAEB' +
  'AgACAQEAAwQDAQUGBgUDAQARBgkBfwFBgIDAAAsHWwYGbWVtb3J5AgAPaGFzaGVyX2ZpbmFs' +
  'aXplAAgQaGFzaGVyX2hlYXBfYmFzZQAJC2hhc2hlcl9pbml0AAoLaGFzaGVyX3NpemUACw1o' +
  'YXNoZXJfdXBkYXRlAAwKsyYQDgAgACABQQEQgYCAgAALhBoCGX8CfiOAgICAAEHAAWsiAySA' +
  'gICAACADQQBBwAD8CwAgASACQQZ0aiEEIAAoAhwhBSAAKAIYIQYgACgCFCEHIAAoAhAhCCAA' +
  'KAIMIQkgACgCCCEKIAAoAgQhCyAAKAIAIQwCQANAIAEgBEYNAUEAIQICQANAIAJBwABGDQEg' +
  'AyACaiABIAJqKAAAIg1B/4H8B3FBCHggDUEYeEH/gfwHcXI2AgAgAkEEaiECDAALCyADIAMo' +
  'AgAiDjYCrAEgAyADKAIEIg82AqgBIAMgAygCCCIQNgKkASADIAMoAgwiETYCoAEgAyALNgJE' +
  'IAMgBzYCTCADIAw2AkAgAyAINgJIIAMgCjYCUCADIAk2AlQgAyAGNgJYIAMgBTYCXCADKAIc' +
  'IQIgAygCGCENIAMoAhQhEiADIAMoAhAiEzYCbCADIBI2AmggAyANNgJkIAMgAjYCYCADKAIs' +
  'IRQgAygCKCEVIAMoAiQhFiADIAMoAiAiFzYCfCADIBY2AnggAyAVNgJ0IAMgFDYCcCADKAI8' +
  'IRggAygCOCEZIAMoAjQhGiADIAMoAjAiGzYCjAEgAyAaNgKIASADIBk2AoQBIAMgGDYCgAEg' +
  'A0GwAWogA0HQAGogA0HAAGogD0GRid2JB2ogDkGY36iUBGoQjoCAgAAgAyADKQK4ATcDWCAD' +
  'IAMpArABNwNQIANBsAFqIANBwABqIANB0ABqIBFBpbfXzX5qIBBBz/eDrntqEI6AgIAAIAMg' +
  'AykCuAE3A0ggAyADKQKwATcDQCADQbABaiADQdAAaiADQcAAaiASQfGjxM8FaiATQduE28oD' +
  'ahCOgICAACADIAMpArgBNwNYIAMgAykCsAE3A1AgA0GwAWogA0HAAGogA0HQAGogAkHVvfHY' +
  'emogDUGkhf6ReWoQjoCAgAAgAyADKQK4ATcDSCADIAMpArABNwNAIANBsAFqIANB0ABqIANB' +
  'wABqIBZBgbaNlAFqIBdBmNWewH1qEI6AgIAAIAMgAykCuAE3A1ggAyADKQKwATcDUCADQbAB' +
  'aiADQcAAaiADQdAAaiAUQcP7sagFaiAVQb6LxqECahCOgICAACADIAMpArgBNwNIIAMgAykC' +
  'sAE3A0AgA0GwAWogA0HQAGogA0HAAGogGkH+4/qGeGogG0H0uvmVB2oQjoCAgAAgAyADKQK4' +
  'ATcDWCADIAMpArABNwNQIANBsAFqIANBwABqIANB0ABqIBhB9OLvjHxqIBlBp43w3nlqEI6A' +
  'gIAAIAMgAykCuAE3A0ggAyADKQKwATcDQCADQZABaiADQaABaiATIANB8ABqIANBgAFqEI+A' +
  'gIAAIAMoApABIQIgAygClAEhDSADQbABaiADQdAAaiADQcAAaiADKAKYAUGGj/n9fmogAygC' +
  'nAEiEkHB0+2kfmoQjoCAgAAgAyADKQK4ATcDWCADIAMpArABNwNQIANBsAFqIANBwABqIANB' +
  '0ABqIAJBzMOyoAJqIA1BxruG/gBqEI6AgIAAIAMgAykCuAE3A0ggAyADKQKwATcDQCADQaAB' +
  'aiADQeAAaiAXIANBgAFqIANBkAFqEI+AgIAAIAMoAqABIQIgAygCpAEhDSADQbABaiADQdAA' +
  'aiADQcAAaiADKAKoAUGqidLTBGogAygCrAEiE0Hv2KTvAmoQjoCAgAAgAyADKQK4ATcDWCAD' +
  'IAMpArABNwNQIANBsAFqIANBwABqIANB0ABqIAJB2pHmtwdqIA1B3NPC5QVqEI6AgIAAIAMg' +
  'AykCuAE3A0ggAyADKQKwATcDQCADQeAAaiADQfAAaiAbIANBkAFqIANBoAFqEI+AgIAAIAMo' +
  'AmAhAiADKAJkIQ0gA0GwAWogA0HQAGogA0HAAGogAygCaEHtjMfBemogAygCbCIUQdKi+cF5' +
  'ahCOgICAACADIAMpArgBNwNYIAMgAykCsAE3A1AgA0GwAWogA0HAAGogA0HQAGogAkHH/+X6' +
  'e2ogDUHIz4yAe2oQjoCAgAAgAyADKQK4ATcDSCADIAMpArABNwNAIANB8ABqIANBgAFqIBIg' +
  'A0GgAWogA0HgAGoQj4CAgAAgAygCcCECIAMoAnQhDSADQbABaiADQdAAaiADQcAAaiADKAJ4' +
  'Qceinq19aiADKAJ8IhJB85eAt3xqEI6AgIAAIAMgAykCuAE3A1ggAyADKQKwATcDUCADQbAB' +
  'aiADQcAAaiADQdAAaiACQefSpKEBaiANQdHGqTZqEI6AgIAAIAMgAykCuAE3A0ggAyADKQKw' +
  'ATcDQCADQYABaiADQZABaiATIANB4ABqIANB8ABqEI+AgIAAIAMoAoABIQIgAygChAEhDSAD' +
  'QbABaiADQdAAaiADQcAAaiADKAKIAUG4wuzwAmogAygCjAEiE0GFldy9AmoQjoCAgAAgAyAD' +
  'KQK4ATcDWCADIAMpArABNwNQIANBsAFqIANBwABqIANB0ABqIAJBk5rgmQVqIA1B/Nux6QRq' +
  'EI6AgIAAIAMgAykCuAE3A0ggAyADKQKwATcDQCADQZABaiADQaABaiAUIANB8ABqIANBgAFq' +
  'EI+AgIAAIAMoApABIQIgAygClAEhDSADQbABaiADQdAAaiADQcAAaiADKAKYAUG7laizB2og' +
  'AygCnAEiFEHU5qmoBmoQjoCAgAAgAyADKQK4ATcDWCADIAMpArABNwNQIANBsAFqIANBwABq' +
  'IANB0ABqIAJBhdnIk3lqIA1BrpKLjnhqEI6AgIAAIAMgAykCuAE3A0ggAyADKQKwATcDQCAD' +
  'QaABaiADQeAAaiASIANBgAFqIANBkAFqEI+AgIAAIAMoAqABIQIgAygCpAEhDSADQbABaiAD' +
  'QdAAaiADQcAAaiADKAKoAUHLzOnAemogAygCrAEiEkGh0f+VemoQjoCAgAAgAyADKQK4ATcD' +
  'WCADIAMpArABNwNQIANBsAFqIANBwABqIANB0ABqIAJBo6Oxu3xqIA1B8JauknxqEI6AgIAA' +
  'IAMgAykCuAE3A0ggAyADKQKwATcDQCADQeAAaiADQfAAaiATIANBkAFqIANBoAFqEI+AgIAA' +
  'IAMoAmAhAiADKAJkIQ0gA0GwAWogA0HQAGogA0HAAGogAygCaEGkjOS0fWogAygCbCITQZnQ' +
  'y4x9ahCOgICAACADIAMpArgBNwNYIAMgAykCsAE3A1AgA0GwAWogA0HAAGogA0HQAGogAkHw' +
  'wKqDAWogDUGF67igf2oQjoCAgAAgAyADKQK4ATcDSCADIAMpArABNwNAIANB8ABqIANBgAFq' +
  'IBQgA0GgAWogA0HgAGoQj4CAgAAgAygCcCECIAMoAnQhDSADQbABaiADQdAAaiADQcAAaiAD' +
  'KAJ4QYjY3fEBaiADKAJ8IhRBloKTzQFqEI6AgIAAIAMgAykCuAE3A1ggAyADKQKwATcDUCAD' +
  'QbABaiADQcAAaiADQdAAaiACQbX5wqUDaiANQczuoboCahCOgICAACADIAMpArgBNwNIIAMg' +
  'AykCsAE3A0AgA0GAAWogA0GQAWogEiADQeAAaiADQfAAahCPgICAACADKAKAASECIAMoAoQB' +
  'IQ0gA0GwAWogA0HQAGogA0HAAGogAygCiAFBytTi9gRqIAMoAowBQbOZ8MgDahCOgICAACAD' +
  'IAMpArgBNwNYIAMgAykCsAE3A1AgA0GwAWogA0HAAGogA0HQAGogAkHz37nBBmogDUHPlPPc' +
  'BWoQjoCAgAAgAyADKQK4ATcDSCADIAMpArABNwNAIANBkAFqIANBoAFqIBMgA0HwAGogA0GA' +
  'AWoQj4CAgAAgAygCkAEhAiADKAKUASENIANBsAFqIANB0ABqIANBwABqIAMoApgBQe/GlcUH' +
  'aiADKAKcAUHuhb6kB2oQjoCAgAAgAyADKQK4ATcDWCADIAMpArABNwNQIANBsAFqIANBwABq' +
  'IANB0ABqIAJBiISc5nhqIA1BlPChpnhqEI6AgIAAIAMgAykCuAE3A0ggAyADKQKwATcDQCAD' +
  'QaABaiADQeAAaiAUIANBgAFqIANBkAFqEI+AgIAAIAMoAqABIQIgAygCpAEhDSADQbABaiAD' +
  'QdAAaiADQcAAaiADKAKoAUHr2cGiemogAygCrAFB+v/7hXlqEI6AgIAAIAMgAykCuAE3A1gg' +
  'AyADKQKwATcDUCADQbABaiADQcAAaiADQdAAaiACQfLxxbN8aiANQffH5vd7ahCOgICAACAD' +
  'IAMpArgBIhw3A0ggAyADKQKwASIdNwNAIAFBwABqIQEgAygCXCAFaiEFIAMoAlggBmohBiAD' +
  'KAJUIAlqIQkgAygCUCAKaiEKIBynIAhqIQggHacgDGohDCADKAJMIAdqIQcgAygCRCALaiEL' +
  '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' +
  '2YMfGc3gWw==';

/**
 * Instantiate the embedded Wasm SHA-256 hasher module.
 * Returns the raw WebAssembly.Instance.exports object.
 * @returns {Promise<{hasher_size: () => number, hasher_init: (p: number) => void,
 *                    hasher_update: (p: number, d: number, n: number) => void,
 *                    hasher_finalize: (p: number, out: number) => void,
 *                    memory: WebAssembly.Memory}>}
 */
export async function loadWasmHasher() {
  const raw = Uint8Array.from(atob(WASM_SHA256_B64), (c) => c.charCodeAt(0));
  const { instance } = await WebAssembly.instantiate(raw);
  return instance.exports;
}

/**
 * Stateless incremental SHA-256 hasher backed by the embedded Wasm module.
 *
 * Each instance owns a slot in the Wasm linear memory (managed by a trivial
 * bump allocator). Call update() with each data chunk, then finalize() once to
 * get the 32-byte hex digest. After finalize() the slot is zeroed — do not
 * reuse the instance.
 */
/**
 * Incremental SHA-256 over the embedded Wasm module.
 *
 * The Rust side is stateless: every call takes a caller-owned slot. Owning the
 * allocation on this side is therefore this class's job, and getting it wrong is
 * quiet — a wrong digest, never a trap. Two rules follow, and both were learned
 * the hard way:
 *
 *  - Nothing may be written below `hasher_heap_base()`. Under that line sit the
 *    module's static data (the round constants among it) and the shadow stack
 *    that `hasher_update` pushes its own frame onto. Writing input there means
 *    the callee overwrites its own argument halfway through reading it.
 *
 *  - Each instance needs its own slot. A Service Worker verifies several
 *    responses at once, and a shared slot means `hasher_init` for one stream
 *    resets another mid-flight, after which one hasher returns the other's
 *    digest.
 *
 * Slots are fixed-size and recycled through a free list, so a page loading a
 * hundred assets does not grow memory a hundred times.
 */

/** Input is copied into Wasm memory in pieces of this size. */
const COPY_WINDOW = 64 * 1024;

class SlotAllocator {
  constructor(exports) {
    this._ex = exports;
    this._mem = exports.memory;
    this._base = exports.hasher_heap_base();
    this._stateSize = exports.hasher_size();
    // state | digest | copy window
    this._slotSize = align8(this._stateSize) + 32 + COPY_WINDOW;
    this._next = 0;
    this._free = [];
  }

  take() {
    const index = this._free.pop() ?? this._next++;
    const start = this._base + index * this._slotSize;
    const end = start + this._slotSize;
    if (end > this._mem.buffer.byteLength) {
      const pages = Math.ceil((end - this._mem.buffer.byteLength) / 65536);
      this._mem.grow(pages);
    }
    return {
      index,
      state: start,
      out: start + align8(this._stateSize),
      copy: start + align8(this._stateSize) + 32,
    };
  }

  release(index) {
    this._free.push(index);
  }
}

function align8(n) {
  return (n + 7) & ~7;
}

const allocators = new WeakMap();

export class WasmSha256Hasher {
  /** @param {WebAssembly.Exports} exports — from loadWasmHasher() */
  constructor(exports) {
    let alloc = allocators.get(exports);
    if (!alloc) {
      alloc = new SlotAllocator(exports);
      allocators.set(exports, alloc);
    }
    this._alloc = alloc;
    this._ex = exports;
    this._mem = exports.memory;
    this._slot = alloc.take();
    this._done = false;
    exports.hasher_init(this._slot.state);
  }

  /** @param {ArrayBufferView|ArrayBuffer} chunk */
  update(chunk) {
    if (this._done) throw new Error('WasmSha256Hasher: already finalized');

    // A stream hands out views into a larger buffer far more often than not, so
    // the offset and length have to be carried across rather than dropped.
    const view =
      chunk instanceof ArrayBuffer
        ? new Uint8Array(chunk)
        : new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);

    for (let off = 0; off < view.byteLength; off += COPY_WINDOW) {
      const piece = view.subarray(off, Math.min(off + COPY_WINDOW, view.byteLength));
      // `memory.grow` detaches the old ArrayBuffer, so the view is rebuilt here
      // rather than cached on the instance.
      new Uint8Array(this._mem.buffer).set(piece, this._slot.copy);
      this._ex.hasher_update(this._slot.state, this._slot.copy, piece.byteLength);
    }
  }

  /**
   * Finalize and return the hex-encoded digest. The slot goes back to the pool.
   * @returns {string}
   */
  finalize() {
    if (this._done) throw new Error('WasmSha256Hasher: already finalized');
    this._done = true;
    this._ex.hasher_finalize(this._slot.state, this._slot.out);
    const digest = new Uint8Array(this._mem.buffer, this._slot.out, 32);
    const out = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
    this._alloc.release(this._slot.index);
    return out;
  }

  /** Release the slot without finalizing — for an aborted stream. */
  dispose() {
    if (this._done) return;
    this._done = true;
    this._alloc.release(this._slot.index);
  }
}
