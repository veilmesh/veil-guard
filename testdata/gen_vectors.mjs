#!/usr/bin/env node
// Generates testdata/conformance_vectors.json — the golden cross-language vectors
// described in SPEC.md §11.
//
// Run:  node testdata/gen_vectors.mjs
//
// Idempotence: Ed25519 keys come from fixed seeds and Ed25519 signing is
// deterministic (RFC 8032), so those vectors regenerate byte-identically. ECDSA
// P-256 signing is randomized, so if conformance_vectors.json already exists this
// script reuses the P-256 private keys AND the frozen P-256 signatures from it
// rather than minting new ones. Delete the file to mint a fresh set — but do not
// do that casually, see SPEC.md §11.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'conformance_vectors.json');

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Buffer.from(s, 'hex');
const sha256 = (b) => createHash('sha256').update(b).digest();
const sha384 = (b) => createHash('sha384').update(b).digest();

// ---------------------------------------------------------------- domain prefixes
const PREFIX = {
  manifest:   Buffer.concat([Buffer.from('veil-guard/manifest/v1', 'ascii'), Buffer.from([0])]),
  rotation:   Buffer.concat([Buffer.from('veil-guard/rotation/v1', 'ascii'), Buffer.from([0])]),
  revocation: Buffer.concat([Buffer.from('veil-guard/revocation/v1', 'ascii'), Buffer.from([0])]),
  keyid:      Buffer.concat([Buffer.from('veil-guard/keyid/v1', 'ascii'), Buffer.from([0])]),
  trustroot:  Buffer.concat([Buffer.from('veil-guard/trustroot/v1', 'ascii'), Buffer.from([0])]),
};

// ---------------------------------------------------------------- key material
// Fixed Ed25519 seeds. Test-only, obviously.
const ED_SEEDS = [
  '0101010101010101010101010101010101010101010101010101010101010101',
  '0202020202020202020202020202020202020202020202020202020202020202',
  '0303030303030303030303030303030303030303030303030303030303030303',
];

const ED_PKCS8_PREFIX = unhex('302e020100300506032b657004220420');

function ed25519FromSeed(seedHex) {
  const der = Buffer.concat([ED_PKCS8_PREFIX, unhex(seedHex)]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  // SPKI for Ed25519 is 44 bytes; the trailing 32 are the raw public key.
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return { priv, pub: spki.subarray(spki.length - 32) };
}

function p256FromPkcs8(pkcs8Hex) {
  const priv = createPrivateKey({ key: unhex(pkcs8Hex), format: 'der', type: 'pkcs8' });
  // SPKI for P-256 is 91 bytes; the trailing 65 are the uncompressed SEC1 point.
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = spki.subarray(spki.length - 65);
  if (pub[0] !== 0x04) throw new Error('expected uncompressed SEC1 point');
  return { priv, pub, pkcs8Hex };
}

function p256Fresh() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  return p256FromPkcs8(hex(pkcs8));
}

const prior = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : null;

const signers = ED_SEEDS.map((seed, i) => {
  const ed = ed25519FromSeed(seed);
  const priorP256 = prior?.signers?.[i]?.p256_private_pkcs8;
  const p256 = priorP256 ? p256FromPkcs8(priorP256) : p256Fresh();
  return {
    role: i < 2 ? 'build' : 'recovery',
    ed_seed: seed,
    ed_priv: ed.priv,
    ed_pub: ed.pub,
    p256_priv: p256.priv,
    p256_pub: p256.pub,
    p256_pkcs8: p256.pkcs8Hex,
  };
});

// ---------------------------------------------------------------- SPEC §4.2 key_id
function keyId(edPub, p256Pub) {
  return sha256(Buffer.concat([PREFIX.keyid, edPub, p256Pub])).subarray(0, 8);
}
for (const s of signers) s.key_id = keyId(s.ed_pub, s.p256_pub);

// Trust root keys, sorted by key_id ascending (SPEC §4.4)
const rootKeys = [...signers].sort((a, b) => Buffer.compare(a.key_id, b.key_id));

// ---------------------------------------------------------------- SPEC §4.5 trust_root_id
const SIGALGS = ['ed25519', 'p256'];
function sigalgMask(algs) {
  return (algs.includes('ed25519') ? 0x01 : 0) | (algs.includes('p256') ? 0x02 : 0);
}
function trustRootBytes(threshold, algs, keys) {
  const head = Buffer.from([threshold, keys.length, sigalgMask(algs)]);
  const body = keys.map((k) => Buffer.concat([k.key_id, k.ed_pub, k.p256_pub]));
  return Buffer.concat([head, ...body]);
}
function trustRootId(threshold, algs, keys) {
  return sha256(Buffer.concat([PREFIX.trustroot, trustRootBytes(threshold, algs, keys)]));
}

const THRESHOLD = 2;
const TR_BYTES = trustRootBytes(THRESHOLD, SIGALGS, rootKeys);
const TR_ID = trustRootId(THRESHOLD, SIGALGS, rootKeys);

const trustRootJson = {
  threshold: THRESHOLD,
  sigalgs: SIGALGS,
  keys: rootKeys.map((k) => ({
    key_id: hex(k.key_id),
    role: k.role,
    ed25519: hex(k.ed_pub),
    p256: hex(k.p256_pub),
  })),
};

// ---------------------------------------------------------------- fixture assets
// Small, fixed contents. The NFC case is the important one: the path is written
// here in NFC (U+00E9) and the vector records the NFD form a macOS scan would
// hand back, so implementations can prove they normalize before comparing.
const NFC_PATH = '/assets/café-9z7y.js';          // é as U+00E9      — what a browser sends
const NFD_PATH = '/assets/café-9z7y.js';        // e + U+0301      — what APFS hands back

const assets = [
  ['/index.html', '<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8"><title>veil-guard fixture</title></head>\n<body><div id="app"></div><script type="module" src="/assets/app-a1b2c3d4.js"></script></body>\n</html>\n', 'text/html'],
  ['/assets/app-a1b2c3d4.js', 'export const build = "fixture";\nconsole.log(build);\n', 'text/javascript'],
  [NFC_PATH, 'export default () => "café";\n', 'text/javascript'],
  ['/assets/core-0f1e2d3c.wasm', '\0asm\x01\0\0\0', 'application/wasm'],
  ['/assets/style-e5f6a7b8.css', ':root{color-scheme:dark}\n', 'text/css'],
].map(([path, body, ct]) => {
  const bytes = Buffer.from(body, 'utf8');
  if (path.normalize('NFC') !== path) throw new Error(`manifest path not NFC: ${path}`);
  return {
    path,
    sha256: hex(sha256(bytes)),
    sha384: hex(sha384(bytes)),
    size: bytes.length,
    content_type: ct,
    _body_hex: hex(bytes),
  };
});
assets.sort((a, b) => Buffer.compare(Buffer.from(a.path, 'utf8'), Buffer.from(b.path, 'utf8')));

const VERSION = 1754500000;   // fixed; SOURCE_DATE_EPOCH equivalent
const NOT_AFTER = VERSION + 180 * 86400;

const manifestObj = {
  spec: 'veil-guard/1',
  version: VERSION,
  not_after: NOT_AFTER,
  sigalgs: SIGALGS,
  trust_root_id: hex(TR_ID),
  trust_root: trustRootJson,
  scope: { include: ['/'], exclude: [] },
  source: {
    commit: '0000000000000000000000000000000000000000',
    repo: 'https://example.invalid/veil-guard-fixture',
    toolchain: { veil_guard: '0.1.0' },
  },
  assets: assets.map(({ _body_hex, ...rest }) => rest),
};

const manifestBytes = Buffer.from(JSON.stringify(manifestObj, null, 2) + '\n', 'utf8');

// ---------------------------------------------------------------- signing
function signEd(signer, prefix, payload) {
  return nodeSign(null, Buffer.concat([prefix, payload]), signer.ed_priv);
}
function signP256(signer, prefix, payload) {
  return nodeSign('sha256', Buffer.concat([prefix, payload]), {
    key: signer.p256_priv,
    dsaEncoding: 'ieee-p1363',   // raw r||s, SPEC §2.1
  });
}

const ALG_ID = { ed25519: 0x01, p256: 0x02 };

// SPEC §5
function buildBundle(entries) {
  const sorted = [...entries].sort((a, b) => {
    const c = Buffer.compare(a.key_id, b.key_id);
    return c !== 0 ? c : a.alg_id - b.alg_id;
  });
  const head = Buffer.alloc(10);
  head.write('VGSIG1', 0, 'ascii');
  head[6] = 0x01;
  head[7] = 0x00;
  head.writeUInt16LE(sorted.length, 8);
  const body = sorted.map((e) => {
    const h = Buffer.alloc(12);
    e.key_id.copy(h, 0);
    h[8] = e.alg_id;
    h[9] = 0x00;
    h.writeUInt16LE(e.sig.length, 10);
    return Buffer.concat([h, e.sig]);
  });
  return Buffer.concat([head, ...body]);
}

// Frozen P-256 signatures: reuse from a prior run when available.
const frozen = new Map();
if (prior?._frozen_p256) for (const [k, v] of Object.entries(prior._frozen_p256)) frozen.set(k, unhex(v));
function frozenP256(tag, signer, prefix, payload) {
  if (frozen.has(tag)) return frozen.get(tag);
  const s = signP256(signer, prefix, payload);
  frozen.set(tag, s);
  return s;
}

// Threshold quorum: signers 0 and 1 (the two build keys), both algorithms.
const quorum = [signers[0], signers[1]];
const manifestEntries = [];
for (const [i, s] of quorum.entries()) {
  manifestEntries.push({ key_id: s.key_id, alg_id: ALG_ID.ed25519, sig: signEd(s, PREFIX.manifest, manifestBytes) });
  manifestEntries.push({ key_id: s.key_id, alg_id: ALG_ID.p256, sig: frozenP256(`manifest.${i}`, s, PREFIX.manifest, manifestBytes) });
}
const bundleValid = buildBundle(manifestEntries);

// One signer only — below the 2-of-3 threshold.
const bundleBelowThreshold = buildBundle(manifestEntries.filter((e) => e.key_id.equals(signers[0].key_id)));

// Signer 0 complete, signer 1 missing its p256 half: signer 1 must not count,
// so the quorum drops to 1 and verification fails. (SPEC §8.1 step 3)
const bundleStrippedAlg = buildBundle(
  manifestEntries.filter((e) => !(e.key_id.equals(signers[1].key_id) && e.alg_id === ALG_ID.p256)),
);

// Signer 1's ed25519 signature present but corrupted: hard fail, not "doesn't count".
const bundleCorruptEntry = buildBundle(
  manifestEntries.map((e) => {
    if (e.key_id.equals(signers[1].key_id) && e.alg_id === ALG_ID.ed25519) {
      const bad = Buffer.from(e.sig);
      bad[0] ^= 0x01;
      return { ...e, sig: bad };
    }
    return e;
  }),
);

// ---------------------------------------------------------------- rotation
const newRootKeys = [...[signers[0], signers[2]]].sort((a, b) => Buffer.compare(a.key_id, b.key_id));
const NEW_TR_ID = trustRootId(THRESHOLD, SIGALGS, newRootKeys);
const rotationObj = {
  spec: 'veil-guard/rotation/1',
  version: VERSION + 3600,
  from_trust_root_id: hex(TR_ID),
  to_trust_root: {
    threshold: THRESHOLD,
    sigalgs: SIGALGS,
    keys: newRootKeys.map((k) => ({
      key_id: hex(k.key_id), role: k.role, ed25519: hex(k.ed_pub), p256: hex(k.p256_pub),
    })),
  },
};
const rotationBytes = Buffer.from(JSON.stringify(rotationObj, null, 2) + '\n', 'utf8');
const rotationEntries = [];
for (const [i, s] of quorum.entries()) {
  rotationEntries.push({ key_id: s.key_id, alg_id: ALG_ID.ed25519, sig: signEd(s, PREFIX.rotation, rotationBytes) });
  rotationEntries.push({ key_id: s.key_id, alg_id: ALG_ID.p256, sig: frozenP256(`rotation.${i}`, s, PREFIX.rotation, rotationBytes) });
}
const bundleRotation = buildBundle(rotationEntries);

// Cross-prefix: the manifest signature, offered as if it signed the rotation.
// Must not verify. (SPEC §3)
const bundleWrongPrefix = buildBundle(manifestEntries);

// ---------------------------------------------------------------- malformed bundles
const malformed = {
  bad_magic:      hex(Buffer.concat([Buffer.from('VGSIG0', 'ascii'), bundleValid.subarray(6)])),
  bad_version:    hex(Buffer.concat([bundleValid.subarray(0, 6), Buffer.from([0x02]), bundleValid.subarray(7)])),
  reserved_set:   hex(Buffer.concat([bundleValid.subarray(0, 7), Buffer.from([0x01]), bundleValid.subarray(8)])),
  trailing_bytes: hex(Buffer.concat([bundleValid, Buffer.from([0x00])])),
  zero_entries:   hex((() => { const b = Buffer.from(bundleValid); b.writeUInt16LE(0, 8); return b.subarray(0, 10); })()),
  truncated_sig:  hex(bundleValid.subarray(0, bundleValid.length - 4)),
  duplicate_pair: hex(buildBundle([...manifestEntries, manifestEntries[0]])),
  unsorted:       hex((() => {
    // Same entries, emitted in reverse order — violates SPEC §5 rule 4.
    const rev = [...manifestEntries].sort((a, b) => {
      const c = Buffer.compare(b.key_id, a.key_id);
      return c !== 0 ? c : b.alg_id - a.alg_id;
    });
    const head = Buffer.alloc(10);
    head.write('VGSIG1', 0, 'ascii'); head[6] = 0x01; head[7] = 0x00;
    head.writeUInt16LE(rev.length, 8);
    const body = rev.map((e) => {
      const h = Buffer.alloc(12);
      e.key_id.copy(h, 0); h[8] = e.alg_id; h[9] = 0x00; h.writeUInt16LE(e.sig.length, 10);
      return Buffer.concat([h, e.sig]);
    });
    return Buffer.concat([head, ...body]);
  })()),
};

// Not malformed: SPEC §5 rule 3 says an unknown alg_id is skipped, not rejected.
// This is the format's only forward-compatibility hook, so it must still be VALID.
const bundleUnknownAlg = buildBundle([
  ...manifestEntries,
  { key_id: signers[2].key_id, alg_id: 0x7f, sig: Buffer.alloc(64, 0xab) },
]);

// ---------------------------------------------------------------- output
const out = {
  _comment: [
    'Golden conformance vectors for the veil-guard protocol. See SPEC.md §11.',
    'GENERATED ONCE by testdata/gen_vectors.mjs. Ed25519 vectors are deterministic and',
    'reproducible; the P-256 signatures under _frozen_p256 are not (ECDSA is randomized)',
    'and are reused across regenerations on purpose. Do not delete them.',
    'All key material here is test-only.',
  ],
  spec: 'veil-guard/1',
  prefixes: Object.fromEntries(Object.entries(PREFIX).map(([k, v]) => [k, hex(v)])),

  signers: signers.map((s) => ({
    role: s.role,
    key_id: hex(s.key_id),
    ed25519_seed: s.ed_seed,
    ed25519_public: hex(s.ed_pub),
    p256_public_sec1_uncompressed: hex(s.p256_pub),
    p256_private_pkcs8: s.p256_pkcs8,
  })),

  derivations: {
    key_id: signers.map((s) => ({
      input_hex: hex(Buffer.concat([PREFIX.keyid, s.ed_pub, s.p256_pub])),
      expect_key_id: hex(s.key_id),
    })),
    trust_root: {
      threshold: THRESHOLD,
      sigalgs: SIGALGS,
      key_order: rootKeys.map((k) => hex(k.key_id)),
      tr_bytes_hex: hex(TR_BYTES),
      expect_trust_root_id: hex(TR_ID),
    },
  },

  hashes: assets.map((a) => ({
    path: a.path,
    body_hex: a._body_hex,
    expect_sha256: a.sha256,
    expect_sha384: a.sha384,
    expect_sri: 'sha384-' + Buffer.from(a.sha384, 'hex').toString('base64'),
  })),

  manifest: {
    payload_utf8_hex: hex(manifestBytes),
    payload_sha256: hex(sha256(manifestBytes)),
    pinned_version: VERSION,
    now_valid: VERSION + 60,
    now_expired: NOT_AFTER + 60,
    cases: [
      { name: 'valid_quorum', bundle_hex: hex(bundleValid), expect: 'VALID' },
      { name: 'below_threshold', bundle_hex: hex(bundleBelowThreshold), expect: 'UNTRUSTED_ROOT' },
      { name: 'stripped_p256_half', bundle_hex: hex(bundleStrippedAlg), expect: 'UNTRUSTED_ROOT',
        note: 'signer 1 lacks p256 so it does not count; quorum falls to 1' },
      { name: 'present_but_invalid', bundle_hex: hex(bundleCorruptEntry), expect: 'TAMPERED',
        note: 'a present signature that fails is fatal, it does not merely fail to count' },
      { name: 'expired_at_now_expired', bundle_hex: hex(bundleValid), expect: 'EXPIRED',
        note: 'evaluate with now = now_expired' },
      { name: 'rollback', bundle_hex: hex(bundleValid), expect: 'ROLLBACK',
        note: 'evaluate with pinned_version = version + 1' },
      { name: 'unknown_alg_id_is_skipped', bundle_hex: hex(bundleUnknownAlg), expect: 'VALID',
        note: 'SPEC §5 rule 3 — forward compatibility, the entry is skipped not rejected' },
    ],
    malformed_bundles: malformed,
  },

  rotation: {
    payload_utf8_hex: hex(rotationBytes),
    bundle_hex: hex(bundleRotation),
    expect: 'ACCEPT',
    expect_new_trust_root_id: hex(NEW_TR_ID),
    replay_pinned_rotation_version: VERSION + 3600,
    replay_expect: 'REJECT',
    replay_note: 'the same statement offered again when its version is already pinned',
    wrong_prefix_bundle_hex: hex(bundleWrongPrefix),
    wrong_prefix_expect: 'REJECT',
    wrong_prefix_note: 'manifest-prefixed signatures must not verify as a rotation (SPEC §3)',
  },

  paths: {
    nfc: [
      { input_nfd_hex: hex(Buffer.from(NFD_PATH, 'utf8')),
        expect_nfc_hex: hex(Buffer.from(NFC_PATH, 'utf8')),
        note: 'macOS APFS hands back NFD (e + U+0301); browsers send NFC (U+00E9). ' +
              'The two byte strings differ, so an implementation that skips normalization ' +
              'will never match this asset.' },
    ],
    reject_before_decoding: ['/assets/%2e%2e/secret.js', '/assets/a%2Fb.js', '/assets/a%5Cb.js', '/assets/a%00.js'],
    reject_after_canonicalization: ['/assets/../secret.js', '/assets//a.js', '/assets/./a.js', 'assets/a.js'],
    query_is_ignored: [
      { url: '/assets/app-a1b2c3d4.js?v=2', expect_key: '/assets/app-a1b2c3d4.js' },
      { url: '/assets/app-a1b2c3d4.js#frag', expect_key: '/assets/app-a1b2c3d4.js' },
    ],
  },

  content_type_equivalence: {
    'text/javascript': ['application/javascript', 'application/x-javascript', 'text/ecmascript', 'application/ecmascript'],
    'application/json': ['text/json'],
    'application/wasm': [],
    'text/css': [],
  },

  _frozen_p256: Object.fromEntries([...frozen].map(([k, v]) => [k, hex(v)])),
};

writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${OUT}`);
console.log(`  signers          : ${signers.length} (threshold ${THRESHOLD})`);
console.log(`  trust_root_id    : ${hex(TR_ID)}`);
console.log(`  manifest payload : ${manifestBytes.length} bytes`);
console.log(`  frozen p256 sigs : ${frozen.size}`);
