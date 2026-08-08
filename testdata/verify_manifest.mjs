#!/usr/bin/env node
// Verify a real signed build with the reference JavaScript verifier.
//
//   node testdata/verify_manifest.mjs <dist-dir> <trust-root.json> [expected-state]
//
// Unlike verify_vectors.mjs, which replays frozen fixtures, this consumes output
// the Rust CLI just produced. It is the JS half of the Rust-signs/JS-verifies
// direction; `tests/cross_language.rs` drives it from `cargo test`.
//
// Exits 0 when the manifest reaches the expected state (default VALID) and every
// asset on disk matches it.

import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { hex, sha256, verifyManifest, detectSupported } from '../runtime/veilguard-verify.mjs';

const [dist, trustRootPath, expected = 'VALID'] = process.argv.slice(2);
if (!dist || !trustRootPath) {
  console.error('usage: verify_manifest.mjs <dist-dir> <trust-root.json> [expected-state]');
  process.exit(2);
}

const payload = new Uint8Array(readFileSync(join(dist, 'veil-guard-manifest.json')));
const bundle = new Uint8Array(readFileSync(join(dist, 'veil-guard-manifest.sig')));
const pinned = JSON.parse(readFileSync(trustRootPath, 'utf8'));

const supported = await detectSupported();
console.log(`engine supports : ${[...supported].join(', ')}`);

const state = await verifyManifest({ payload, bundle, pinned, supported });
console.log(`manifest state  : ${state}`);

if (state !== expected) {
  console.error(`FAIL: expected ${expected}`);
  process.exit(1);
}

// A hard failure means the contents were never authenticated, so there is nothing
// meaningful to compare the files on disk against.
if (['TAMPERED', 'ROLLBACK', 'UNTRUSTED_ROOT', 'UNSUPPORTED'].includes(state)) {
  console.log('hard failure reproduced as expected');
  process.exit(0);
}

const manifest = JSON.parse(new TextDecoder().decode(payload));
let checked = 0;
const problems = [];

for (const entry of manifest.assets) {
  const path = join(dist, entry.path);
  let bytes;
  try {
    bytes = new Uint8Array(readFileSync(path));
  } catch {
    problems.push(`missing ${entry.path}`);
    continue;
  }
  let ok = true;
  if (hex(await sha256(bytes)) !== entry.sha256) {
    problems.push(`sha256 mismatch  ${entry.path}`);
    ok = false;
  }
  if (statSync(path).size !== entry.size) {
    problems.push(`size mismatch    ${entry.path}`);
    ok = false;
  }
  if (ok) checked++;
}

console.log(`assets matching : ${checked}/${manifest.assets.length}`);
if (problems.length) {
  for (const p of problems) console.log(`  FAIL ${p}`);
  console.error(`FAIL: ${problems.length} problem(s)`);
  process.exit(1);
}
console.log('OK');
