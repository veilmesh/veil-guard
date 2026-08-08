#!/usr/bin/env node
// Checks the reference JavaScript verifier against the golden vectors.
// See SPEC.md §11.
//
// Run:  node testdata/verify_vectors.mjs
//       deno run --allow-read testdata/verify_vectors.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  ALL_ALGS,
  PREFIX,
  contentTypeMatches,
  hex,
  keyId,
  requestKey,
  sha256,
  sha384,
  trustRootId,
  unhex,
  verifyManifest,
  verifyRotation,
} from '../runtime/veilguard-verify.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, 'conformance_vectors.json'), 'utf8'));

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

const payload = unhex(V.manifest.payload_utf8_hex);
const manifest = JSON.parse(new TextDecoder().decode(payload));
const pinned = manifest.trust_root;

console.log('\ndomain prefixes');
for (const [name, expected] of Object.entries(V.prefixes)) {
  check(`prefix ${name}`, hex(PREFIX[name]) === expected);
}

console.log('\nderivations');
for (const [i, d] of V.derivations.key_id.entries()) {
  const s = V.signers[i];
  check(
    `key_id[${i}]`,
    (await keyId(s.ed25519_public, s.p256_public_sec1_uncompressed)) === d.expect_key_id,
  );
}
check(
  'trust_root_id',
  (await trustRootId(pinned)) === V.derivations.trust_root.expect_trust_root_id,
);
check(
  'manifest.trust_root_id matches payload',
  manifest.trust_root_id === V.derivations.trust_root.expect_trust_root_id,
);

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
  const pinnedVersion =
    c.name === 'rollback' ? manifest.version + 1 : V.manifest.pinned_version;
  const now =
    c.name === 'expired_at_now_expired' ? V.manifest.now_expired : V.manifest.now_valid;
  const got = await verifyManifest({
    payload,
    bundle: unhex(c.bundle_hex),
    pinned,
    pinnedVersion,
    now,
  });
  check(`${c.name} => ${c.expect}`, got === c.expect, `got ${got}`);
}

console.log('\nmalformed bundles (all must be TAMPERED)');
for (const [name, h] of Object.entries(V.manifest.malformed_bundles)) {
  const got = await verifyManifest({
    payload,
    bundle: unhex(h),
    pinned,
    pinnedVersion: V.manifest.pinned_version,
    now: V.manifest.now_valid,
  });
  check(name, got === 'TAMPERED', `got ${got}`);
}

console.log('\nrestricted verifier algorithm sets (SPEC §8.1)');
{
  const find = (n) => unhex(V.manifest.cases.find((c) => c.name === n).bundle_hex);
  const valid = find('valid_quorum');
  const stripped = find('stripped_p256_half');
  const run = (bundle, algs) =>
    verifyManifest({
      payload,
      bundle,
      pinned,
      pinnedVersion: V.manifest.pinned_version,
      now: V.manifest.now_valid,
      supported: new Set(algs),
    });

  check('p256-only verifier accepts a dual-signed manifest', (await run(valid, ['p256'])) === 'VALID');
  check(
    'ed25519-only verifier accepts a dual-signed manifest',
    (await run(valid, ['ed25519'])) === 'VALID',
  );
  check('verifier with no shared algorithm => UNSUPPORTED', (await run(valid, [])) === 'UNSUPPORTED');

  // An attacker holding only the ed25519 halves cannot reach the threshold on a
  // verifier that also implements p256.
  check(
    'dual verifier rejects an ed25519-only forgery',
    (await run(stripped, ['ed25519', 'p256'])) === 'UNTRUSTED_ROOT',
  );
  check('p256-only verifier also rejects it', (await run(stripped, ['p256'])) === 'UNTRUSTED_ROOT');

  // Documented residual weakness, asserted so it can never become accidental.
  check(
    'ed25519-only verifier accepts it — documented residual weakness',
    (await run(stripped, ['ed25519'])) === 'VALID',
  );
}

console.log('\nrotation');
{
  const rotPayload = unhex(V.rotation.payload_utf8_hex);
  const bundle = unhex(V.rotation.bundle_hex);
  check(
    'valid rotation accepted',
    (await verifyRotation({ payload: rotPayload, bundle, pinned })) === 'ACCEPT',
  );
  check(
    'replay rejected',
    (await verifyRotation({
      payload: rotPayload,
      bundle,
      pinned,
      pinnedRotationVersion: V.rotation.replay_pinned_rotation_version,
    })) === 'REJECT',
  );
  check(
    'manifest-prefixed signature rejected as rotation',
    (await verifyRotation({
      payload: rotPayload,
      bundle: unhex(V.rotation.wrong_prefix_bundle_hex),
      pinned,
    })) === 'REJECT',
  );
  const rot = JSON.parse(new TextDecoder().decode(rotPayload));
  check(
    'new trust_root_id',
    (await trustRootId(rot.to_trust_root)) === V.rotation.expect_new_trust_root_id,
  );
}

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
check(
  'manifest contains the NFC path',
  manifest.assets.some((a) => a.path === new TextDecoder().decode(unhex(V.paths.nfc[0].expect_nfc_hex))),
);

console.log('\ncontent-type equivalence');
for (const [canonical, aliases] of Object.entries(V.content_type_equivalence)) {
  for (const alias of aliases) {
    check(`${canonical} accepts ${alias}`, contentTypeMatches(canonical, alias));
  }
}
check('charset parameter is ignored', contentTypeMatches('text/javascript', 'text/javascript; charset=utf-8'));
check('unrelated types do not match', !contentTypeMatches('application/wasm', 'text/javascript'));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
