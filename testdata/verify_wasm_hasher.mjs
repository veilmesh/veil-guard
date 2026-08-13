#!/usr/bin/env node
// The embedded Wasm SHA-256 hasher — SPEC.md §8.3 (streamed response verification).
//
// Run:  node testdata/verify_wasm_hasher.mjs
//
// This exists because every defect the streaming path shipped with was in code no
// test touched, and each one failed the same way: a wrong digest, silently. There
// is no trap to catch, no exception to surface — the hash simply differs, and a
// healthy file is reported as tampered. So the whole point here is to compare
// against an independent implementation on inputs shaped like the ones a
// ReadableStream actually produces.

import { createHash } from 'node:crypto';
import { loadWasmHasher, WasmSha256Hasher } from '../runtime/veilguard-verify.mjs';

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

const exports_ = await loadWasmHasher();

const reference = (chunks) => {
  const h = createHash('sha256');
  for (const c of chunks) h.update(c);
  return h.digest('hex');
};
const wasm = (chunks) => {
  const h = new WasmSha256Hasher(exports_);
  for (const c of chunks) h.update(c);
  return h.finalize();
};
const agrees = (chunks) => wasm(chunks) === reference(chunks);

console.log('\nmodule');
check('exports the documented ABI', ['hasher_size', 'hasher_init', 'hasher_update', 'hasher_finalize', 'hasher_heap_base', 'memory'].every((n) => n in exports_));
check(
  'reports a heap base above its own static data and stack',
  exports_.hasher_heap_base() > exports_.hasher_size(),
  `heap_base=${exports_.hasher_heap_base()}`,
);

console.log('\ndigests agree with an independent implementation');
check('empty input', agrees([]));
check('abc', agrees([Buffer.from('abc')]));
check('exactly one block', agrees([Buffer.alloc(64, 7)]));
check('one byte over a block', agrees([Buffer.alloc(65, 7)]));
check('many small chunks', agrees(Array.from({ length: 1000 }, (_, i) => Buffer.from([i & 255]))));

console.log('\nchunk sizes (regression: input was copied into the shadow stack)');
// The copy window is 64 KiB and the module's stack sat at 1 MiB, so anything
// approaching or exceeding either boundary used to come back wrong.
for (const size of [64 * 1024, 64 * 1024 + 1, 512 * 1024, 1024 * 1024, 4 * 1024 * 1024]) {
  check(`single chunk of ${size} bytes`, agrees([Buffer.alloc(size, 0x5a)]));
}

console.log('\nviews (regression: byteOffset and byteLength were dropped)');
// A ReadableStream hands out views into a shared buffer far more often than it
// hands out whole buffers. Hashing `chunk.buffer` reads the neighbours too.
const backing = new Uint8Array(4096).fill(0xaa);
backing.set([1, 2, 3, 4, 5, 6, 7, 8], 1024);
const slice = new Uint8Array(backing.buffer, 1024, 8);
check(
  'a view is hashed, not its backing buffer',
  wasm([slice]) === reference([Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])]),
);
check('a whole ArrayBuffer is accepted too', wasm([backing.buffer]) === reference([backing]));

console.log('\nconcurrent hashers (regression: every instance shared one slot)');
// A worker verifies several responses at once. Interleaved instances used to
// reset each other, after which one returned another's digest.
{
  const a = Buffer.from('file-A');
  const b = Buffer.from('file-B');
  const c = Buffer.alloc(200_000, 3);
  const ha = new WasmSha256Hasher(exports_);
  ha.update(a);
  const hb = new WasmSha256Hasher(exports_);
  hb.update(b);
  const hc = new WasmSha256Hasher(exports_);
  hc.update(c);
  const da = ha.finalize();
  const dc = hc.finalize();
  const db = hb.finalize();
  check('interleaved instances keep their own state', da === reference([a]) && db === reference([b]) && dc === reference([c]));
}

console.log('\nslot lifecycle');
{
  const before = exports_.memory.buffer.byteLength;
  for (let i = 0; i < 200; i++) {
    const h = new WasmSha256Hasher(exports_);
    h.update(Buffer.alloc(1000, i & 255));
    h.finalize();
  }
  check('finalized slots are reused rather than leaked', exports_.memory.buffer.byteLength === before);

  const h = new WasmSha256Hasher(exports_);
  h.update(Buffer.from('x'));
  h.finalize();
  let threw = false;
  try {
    h.finalize();
  } catch {
    threw = true;
  }
  check('a second finalize is refused', threw);

  let threwUpdate = false;
  try {
    h.update(Buffer.from('y'));
  } catch {
    threwUpdate = true;
  }
  check('update after finalize is refused', threwUpdate);

  const aborted = new WasmSha256Hasher(exports_);
  aborted.update(Buffer.from('partial'));
  aborted.dispose();
  check('dispose releases a slot for an abandoned stream', agrees([Buffer.from('after dispose')]));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
