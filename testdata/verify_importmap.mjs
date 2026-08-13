#!/usr/bin/env node
// Import map integrity, checked against the output of a real `sign` run.
//
//   node testdata/verify_importmap.mjs <dist-dir>
//
// The Rust tests check the injector in isolation. This checks the thing a browser
// will actually receive: that every HTML file in a signed build still parses, that
// each import map's JSON survived being spliced into, and that the integrity block
// covers every local URL the map names — `scopes` as well as `imports`. A partial
// block is worse than none, because the browser refuses the modules it does not
// cover.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const dist = process.argv[2];
if (!dist) {
  console.error('usage: verify_importmap.mjs <dist-dir>');
  process.exit(2);
}

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

function htmlFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...htmlFiles(p));
    else if (name.endsWith('.html')) out.push(p);
  }
  return out;
}

const manifest = JSON.parse(readFileSync(join(dist, 'veil-guard-manifest.json'), 'utf8'));
const bySha384 = new Map(manifest.assets.map((a) => [a.path, a.sha384]));

/** Every local URL an import map names, from `imports` and from every scope. */
function namedUrls(map) {
  const urls = [];
  const take = (obj) => {
    for (const v of Object.values(obj ?? {})) {
      if (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//')) urls.push(v);
    }
  };
  take(map.imports);
  for (const scope of Object.values(map.scopes ?? {})) take(scope);
  return urls;
}

const b64 = (hexStr) => Buffer.from(hexStr, 'hex').toString('base64');

let mapsSeen = 0;
for (const file of htmlFiles(dist)) {
  const html = readFileSync(file, 'utf8');
  const rx = /<script\b[^>]*\btype=["']importmap["'][^>]*>([\s\S]*?)<\/script>/gi;
  for (const m of html.matchAll(rx)) {
    mapsSeen++;
    const label = file.slice(dist.length) || file;

    let map;
    try {
      map = JSON.parse(m[1]);
    } catch (e) {
      check(`${label}: import map is still valid JSON after injection`, false, e.message);
      continue;
    }
    check(`${label}: import map is still valid JSON after injection`, true);

    const named = namedUrls(map);
    const covered = Object.keys(map.integrity ?? {});
    const missing = named.filter((u) => bySha384.has(u) && !covered.includes(u));
    check(
      `${label}: every signed URL the map names is covered (${covered.length}/${named.length})`,
      missing.length === 0,
      missing.join(', '),
    );

    for (const [url, value] of Object.entries(map.integrity ?? {})) {
      const expected = bySha384.get(url);
      check(
        `${label}: ${url} carries the digest from the manifest`,
        expected !== undefined && value === `sha384-${b64(expected)}`,
        `got ${value}`,
      );
    }

    // A cross-origin module cannot be covered by a manifest that describes this
    // origin, and inventing a digest for one would break the page outright.
    const foreign = Object.keys(map.integrity ?? {}).filter((u) => !u.startsWith('/'));
    check(`${label}: no cross-origin URL was given a digest`, foreign.length === 0, foreign.join(', '));
  }
}

if (mapsSeen === 0) {
  console.log('  --   no <script type="importmap"> in this build; nothing to check');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
