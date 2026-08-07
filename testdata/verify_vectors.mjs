#!/usr/bin/env node
// Reference JavaScript verifier for the veil-guard protocol, checked against
// testdata/conformance_vectors.json. See SPEC.md §8.
//
// Run:  node testdata/verify_vectors.mjs
//       deno run --allow-read testdata/verify_vectors.mjs
//
// This file is deliberately written against the plain WebCrypto surface that a
// Service Worker has — no Node-only crypto, no dependencies — so that the Tier 1
// runtime can be derived from it directly. The Rust CLI must produce identical
// verdicts for every case in the vector file.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const subtle = globalThis.crypto.subtle;
const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, 'conformance_vectors.json'), 'utf8'));

const unhex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const cat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const PREFIX = Object.fromEntries(Object.entries(V.prefixes).map(([k, v]) => [k, unhex(v)]));
const ALG_ID = { 0x01: 'ed25519', 0x02: 'p256' };

// ------------------------------------------------------------------ primitives
const sha256 = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
const sha384 = async (b) => new Uint8Array(await subtle.digest('SHA-384', b));

async function verifySig(alg, pubRaw, sig, data) {
  try {
    if (alg === 'ed25519') {
      const k = await subtle.importKey('raw', pubRaw, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, k, sig, data);
    }
    if (alg === 'p256') {
      // SPEC §2.1: 65-byte uncompressed SEC1 point in, raw r||s signature in.
      const k = await subtle.importKey('raw', pubRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, data);
    }
  } catch { return false; }
  return false;
}

// A real runtime probes this once at install. Node 22 and current browsers have
// both; older engines have only p256, which SPEC §8.1 explicitly accommodates.
const ALL_ALGS = new Set(['ed25519', 'p256']);

// ------------------------------------------------------------------ SPEC §5
class BundleError extends Error {}

function parseBundle(bytes) {
  if (bytes.length < 10) throw new BundleError('short header');
  const magic = String.fromCharCode(...bytes.subarray(0, 6));
  if (magic !== 'VGSIG1') throw new BundleError('bad magic');
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
    const a = entries[i - 1], b = entries[i];
    const c = compareBytes(a.keyId, b.keyId);
    if (c > 0 || (c === 0 && a.algId > b.algId)) throw new BundleError('entries not sorted');
    if (c === 0 && a.algId === b.algId) throw new BundleError('duplicate (key_id, alg_id)');
  }
  return entries;
}

function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

// ------------------------------------------------------------------ SPEC §4.5
async function trustRootId(root) {
  const mask = (root.sigalgs.includes('ed25519') ? 1 : 0) | (root.sigalgs.includes('p256') ? 2 : 0);
  const parts = [Uint8Array.from([root.threshold, root.keys.length, mask])];
  for (const k of root.keys) parts.push(unhex(k.key_id), unhex(k.ed25519), unhex(k.p256));
  return hex(await sha256(cat(PREFIX.trustroot, cat(...parts))));
}

async function keyId(edPubHex, p256PubHex) {
  const d = await sha256(cat(PREFIX.keyid, unhex(edPubHex), unhex(p256PubHex)));
  return hex(d.subarray(0, 8));
}

// ------------------------------------------------------------------ SPEC §8.1
async function checkThreshold(payload, entries, pinned, prefix, supported = ALL_ALGS) {
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
      // A present signature that fails is fatal — this is the downgrade defense.
      if (!(await verifySig(alg, pub, e.sig, data))) return { state: 'TAMPERED', qualifying };
      present.push(alg);
    }
    if (present.length === active.length) qualifying++;
  }
  return { state: null, qualifying };
}

async function verifyManifest({ payload, bundle, pinned, pinnedVersion, now, supported = ALL_ALGS }) {
  let entries;
  try { entries = parseBundle(bundle); } catch { return 'TAMPERED'; }

  const t = await checkThreshold(payload, entries, pinned, PREFIX.manifest, supported);
  if (t.state) return t.state;
  if (t.qualifying < pinned.threshold) return 'UNTRUSTED_ROOT';

  let m;
  try { m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)); } catch { return 'TAMPERED'; }

  if (m.spec !== 'veil-guard/1') return 'TAMPERED';
  if ((await trustRootId(m.trust_root)) !== m.trust_root_id) return 'TAMPERED';
  if (m.trust_root_id !== (await trustRootId(pinned))) return 'UNTRUSTED_ROOT';
  if (JSON.stringify(m.sigalgs) !== JSON.stringify(m.trust_root.sigalgs)) return 'TAMPERED';
  if (!Number.isSafeInteger(m.version) || !Number.isSafeInteger(m.not_after)) return 'TAMPERED';
  if (m.not_after <= m.version) return 'TAMPERED';

  for (let i = 1; i < m.assets.length; i++) {
    const a = m.assets[i - 1].path, b = m.assets[i].path;
    if (!(a < b)) return 'TAMPERED';                       // sorted, no duplicates
    if (b.normalize('NFC') !== b) return 'TAMPERED';        // SPEC §7 step 3
  }

  if (m.version < pinnedVersion) return 'ROLLBACK';
  if (now > m.not_after) return 'EXPIRED';
  return 'VALID';
}

// ------------------------------------------------------------------ SPEC §9.1
async function verifyRotation({ payload, bundle, pinned, pinnedRotationVersion }) {
  let entries;
  try { entries = parseBundle(bundle); } catch { return 'REJECT'; }

  const t = await checkThreshold(payload, entries, pinned, PREFIX.rotation);
  if (t.state || t.qualifying < pinned.threshold) return 'REJECT';

  let r;
  try { r = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)); } catch { return 'REJECT'; }
  if (r.spec !== 'veil-guard/rotation/1') return 'REJECT';
  if (r.from_trust_root_id !== (await trustRootId(pinned))) return 'REJECT';
  if (!(r.version > pinnedRotationVersion)) return 'REJECT';   // strictly greater — anti-replay
  const nk = r.to_trust_root;
  if (!(nk.threshold >= 1 && nk.threshold <= nk.keys.length && nk.keys.length <= 16)) return 'REJECT';
  return 'ACCEPT';
}

// ------------------------------------------------------------------ SPEC §7.1
function requestKey(rawPathname) {
  if (/%2f|%5c|%2e%2e|%00/i.test(rawPathname)) return null;    // reject before decoding
  let p;
  try { p = decodeURIComponent(rawPathname); } catch { return null; }
  p = p.normalize('NFC');
  if (p.includes('\\') || p.includes('//') || p.includes('\0')) return null;
  if (!p.startsWith('/')) return null;
  if (p.split('/').some((c, i) => i > 0 && (c === '.' || c === '..'))) return null;
  return p;
}

// ------------------------------------------------------------------ harness
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => {
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}${detail ? ' — ' + detail : ''}`); }
};

const payload = unhex(V.manifest.payload_utf8_hex);
const manifest = JSON.parse(new TextDecoder().decode(payload));
const pinned = manifest.trust_root;

console.log('\nderivations');
for (const [i, d] of V.derivations.key_id.entries()) {
  const s = V.signers[i];
  check(`key_id[${i}]`, (await keyId(s.ed25519_public, s.p256_public_sec1_uncompressed)) === d.expect_key_id);
}
check('trust_root_id', (await trustRootId(pinned)) === V.derivations.trust_root.expect_trust_root_id);
check('manifest.trust_root_id matches payload', manifest.trust_root_id === V.derivations.trust_root.expect_trust_root_id);

console.log('\nhashes and SRI');
for (const h of V.hashes) {
  const body = unhex(h.body_hex);
  check(`sha256 ${h.path}`, hex(await sha256(body)) === h.expect_sha256);
  check(`sha384 ${h.path}`, hex(await sha384(body)) === h.expect_sha384);
  const b64 = Buffer.from(unhex(h.expect_sha384)).toString('base64');
  check(`sri    ${h.path}`, `sha384-${b64}` === h.expect_sri);
}

console.log('\nmanifest state machine');
for (const c of V.manifest.cases) {
  const pinnedVersion = c.name === 'rollback' ? manifest.version + 1 : V.manifest.pinned_version;
  const now = c.name === 'expired_at_now_expired' ? V.manifest.now_expired : V.manifest.now_valid;
  const got = await verifyManifest({ payload, bundle: unhex(c.bundle_hex), pinned, pinnedVersion, now });
  check(`${c.name} => ${c.expect}`, got === c.expect, `got ${got}`);
}

console.log('\nmalformed bundles (all must be TAMPERED)');
for (const [name, h] of Object.entries(V.manifest.malformed_bundles)) {
  const got = await verifyManifest({
    payload, bundle: unhex(h), pinned,
    pinnedVersion: V.manifest.pinned_version, now: V.manifest.now_valid,
  });
  check(name, got === 'TAMPERED', `got ${got}`);
}

console.log('\nrestricted verifier algorithm sets (SPEC §8.1)');
{
  const valid = unhex(V.manifest.cases.find((c) => c.name === 'valid_quorum').bundle_hex);
  const stripped = unhex(V.manifest.cases.find((c) => c.name === 'stripped_p256_half').bundle_hex);
  const base = { payload, pinned, pinnedVersion: V.manifest.pinned_version, now: V.manifest.now_valid };
  const run = (bundle, algs) => verifyManifest({ ...base, bundle, supported: new Set(algs) });

  check('p256-only verifier accepts a dual-signed manifest',
    (await run(valid, ['p256'])) === 'VALID');
  check('ed25519-only verifier accepts a dual-signed manifest',
    (await run(valid, ['ed25519'])) === 'VALID');
  check('verifier with no shared algorithm => UNSUPPORTED',
    (await run(valid, ['dilithium5'])) === 'UNSUPPORTED');

  // The downgrade defense: an attacker holding only the ed25519 halves cannot get a
  // dual-algorithm verifier to accept, because signer 1's missing p256 half stops it
  // from counting toward the threshold.
  check('dual verifier rejects an ed25519-only forgery',
    (await run(stripped, ['ed25519', 'p256'])) === 'UNTRUSTED_ROOT');
  check('p256-only verifier also rejects it',
    (await run(stripped, ['p256'])) === 'UNTRUSTED_ROOT');

  // Documented residual weakness, asserted so it can never become accidental: a
  // verifier that implements only ed25519 is protected only by ed25519, so the same
  // bundle passes there. SPEC §8.1, final paragraph.
  check('ed25519-only verifier accepts it — documented residual weakness',
    (await run(stripped, ['ed25519'])) === 'VALID');
}

console.log('\nrotation');
const rotPayload = unhex(V.rotation.payload_utf8_hex);
check('valid rotation accepted',
  (await verifyRotation({ payload: rotPayload, bundle: unhex(V.rotation.bundle_hex), pinned, pinnedRotationVersion: 0 })) === 'ACCEPT');
check('replay rejected',
  (await verifyRotation({ payload: rotPayload, bundle: unhex(V.rotation.bundle_hex), pinned, pinnedRotationVersion: V.rotation.replay_pinned_rotation_version })) === 'REJECT');
check('manifest-prefixed signature rejected as rotation',
  (await verifyRotation({ payload: rotPayload, bundle: unhex(V.rotation.wrong_prefix_bundle_hex), pinned, pinnedRotationVersion: 0 })) === 'REJECT');
check('new trust_root_id', (await trustRootId(JSON.parse(new TextDecoder().decode(rotPayload)).to_trust_root)) === V.rotation.expect_new_trust_root_id);

console.log('\npath canonicalization');
for (const c of V.paths.nfc) {
  const got = new TextDecoder().decode(unhex(c.input_nfd_hex)).normalize('NFC');
  check('NFD input normalizes to manifest form', got === new TextDecoder().decode(unhex(c.expect_nfc_hex)));
  check('NFD and NFC really differ as bytes', c.input_nfd_hex !== c.expect_nfc_hex);
}
for (const p of V.paths.reject_before_decoding) check(`reject ${p}`, requestKey(p) === null);
for (const p of V.paths.reject_after_canonicalization) check(`reject ${p}`, requestKey(p) === null);
for (const c of V.paths.query_is_ignored) {
  const path = new URL(c.url, 'https://example.invalid').pathname;
  check(`key of ${c.url}`, requestKey(path) === c.expect_key);
}
check('manifest contains the NFC path',
  manifest.assets.some((a) => a.path === new TextDecoder().decode(unhex(V.paths.nfc[0].expect_nfc_hex))));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
