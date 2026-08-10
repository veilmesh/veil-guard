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
