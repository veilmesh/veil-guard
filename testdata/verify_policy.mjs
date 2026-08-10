#!/usr/bin/env node
// Tier 1 decision logic — SPEC.md §8.2, §8.3, §9.1.
//
// Run:  node testdata/verify_policy.mjs
//
// These are the rules that decide whether code runs. They are pure functions in
// runtime/veilguard-policy.mjs precisely so they can be checked here, without a
// browser, a Cache Storage or an IndexedDB standing in the way.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  applyRotationChain,
  decideRequest,
  decideResponse,
  inScope,
  isHardFailure,
  pinTransition,
  presentationFor,
  MAX_ROTATION_CHAIN,
} from '../runtime/veilguard-policy.mjs';
import { requestKey as requestKeyOf, unhex } from '../runtime/veilguard-verify.mjs';

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

const ORIGIN = 'https://app.example';
const manifest = {
  scope: { include: ['/'], exclude: ['/media/'] },
  assets: [
    { path: '/assets/app.js', sha256: 'aa', sha384: 'bb', size: 10, content_type: 'text/javascript' },
    { path: '/media/clip.mp4', sha256: 'cc', sha384: 'dd', size: 99, content_type: 'video/mp4' },
  ],
};
const entry = manifest.assets[0];
const req = (url, extra = {}) =>
  decideRequest({ url, origin: ORIGIN, manifestState: 'VALID', manifest, ...extra });

console.log('\nscope (SPEC §8.3)');
check('root include matches everything', inScope('/a/b.js', { include: ['/'], exclude: [] }));
check('exclude wins over include', !inScope('/media/x.mp4', manifest.scope));
check(
  'prefixes match on segment boundaries',
  inScope('/apiary.js', { include: ['/'], exclude: ['/api'] }),
  'an /api exclusion must not swallow /apiary.js',
);
check('exact prefix path is excluded', !inScope('/api', { include: ['/'], exclude: ['/api'] }));
check('absent scope defaults to everything', inScope('/x.js', undefined));

console.log('\nrequest decisions (SPEC §8.3)');
check('cross-origin passes through', req('https://cdn.other/x.js').outcome === 'PASSTHROUGH');
check(
  'the manifest itself is never allowlisted against itself',
  req(`${ORIGIN}/veil-guard-manifest.json`).outcome === 'PASSTHROUGH',
);
check('manifested asset is checked', req(`${ORIGIN}/assets/app.js`).outcome === 'CHECK');
check(
  'unmanifested same-origin asset is blocked',
  req(`${ORIGIN}/assets/injected.js`).outcome === 'BLOCK_UNMANIFESTED',
);
check('excluded path passes through', req(`${ORIGIN}/media/clip.mp4`).outcome === 'PASSTHROUGH');
check(
  'query strings do not change the key',
  req(`${ORIGIN}/assets/app.js?v=2`).outcome === 'CHECK',
);
// The URL parser collapses percent-encoded dot segments before a Service Worker
// ever sees them — `/assets/%2e%2e/secret.js` arrives as `/secret.js`, and that is
// also the path the browser puts on the wire, so the worker and the server agree.
// The traversal is therefore not a confusion risk here; the resulting path is just
// an ordinary lookup, and it is refused because nothing signed it.
check(
  'an encoded traversal is collapsed by the URL parser',
  new URL(`${ORIGIN}/assets/%2e%2e/secret.js`).pathname === '/secret.js',
);
check(
  'and the collapsed path is still refused, as unmanifested',
  req(`${ORIGIN}/assets/%2e%2e/secret.js`).outcome === 'BLOCK_UNMANIFESTED',
);
// Encoded separators are a different matter: the URL parser leaves them encoded,
// so the worker and the origin server can still disagree about how many path
// segments there are. These must be refused outright.
check(
  'encoded separators survive parsing and are blocked',
  new URL(`${ORIGIN}/assets/a%2Fb.js`).pathname === '/assets/a%2Fb.js' &&
    req(`${ORIGIN}/assets/a%2Fb.js`).outcome === 'BLOCK_TAMPER',
);
check(
  'navigations are flagged so they keep their redirect mode',
  req(`${ORIGIN}/assets/app.js`, { destination: 'document' }).isNavigation === true,
);

console.log('\ndirectory-style URLs (regression)');
// Found by running Tier 1 in a browser: `/` was rejected as an illegal path, so
// veil-guard blocked the home page of the site it was protecting. Every static
// host serves a directory URL from its index document, and the manifest lists
// files, so the lookup has to bridge that.
const withIndex = {
  scope: { include: ['/'], exclude: [] },
  assets: [
    { path: '/index.html', sha256: 'ii', sha384: 'jj', size: 5, content_type: 'text/html' },
    { path: '/assets/app.js', sha256: 'aa', sha384: 'bb', size: 10, content_type: 'text/javascript' },
  ],
};
const nav = (url) =>
  decideRequest({ url, origin: ORIGIN, destination: 'document', manifestState: 'VALID', manifest: withIndex });

check('the root path is a legal request key', requestKeyOf('/') === '/');
check('a directory path is a legal request key', requestKeyOf('/blog/') === '/blog/');
check('an interior empty component is still illegal', requestKeyOf('/a//b.js') === null);
check(
  'the home page resolves to its index document',
  nav(`${ORIGIN}/`).outcome === 'CHECK' && nav(`${ORIGIN}/`).entry.path === '/index.html',
);
check(
  'an unmatched navigation passes through rather than blanking the site',
  nav(`${ORIGIN}/blog/`).outcome === 'PASSTHROUGH',
);
check(
  'but an unmatched subresource is still refused',
  decideRequest({ url: `${ORIGIN}/blog/x.js`, origin: ORIGIN, manifestState: 'VALID', manifest: withIndex })
    .outcome === 'BLOCK_UNMANIFESTED',
);

console.log('\nextensionless navigations (SPEC §7.1.1 step 3)');
// A static site generator emits flat files: /faq is served from faq.html. Without
// the opt-in those documents match nothing and pass through unverified; with it they
// are checked like any other asset. It stays opt-in because a host with an SPA
// fallback answers /faq with index.html, and applying the rule there would compare
// the wrong bytes and block a healthy deploy.
const flatAssets = [
  { path: '/faq.html', sha256: 'ff', sha384: 'gg', size: 7, content_type: 'text/html' },
  { path: '/index.html', sha256: 'ii', sha384: 'jj', size: 5, content_type: 'text/html' },
];
const flatOff = { scope: { include: ['/'], exclude: [] }, assets: flatAssets };
const flatOn = { scope: { include: ['/'], exclude: [], html_extension: true }, assets: flatAssets };
const navIn = (manifest, url, destination = 'document') =>
  decideRequest({ url, origin: ORIGIN, destination, manifestState: 'VALID', manifest });

check(
  'off by default: /faq is not resolved against faq.html',
  navIn(flatOff, `${ORIGIN}/faq`).outcome === 'PASSTHROUGH',
);
check(
  'opt-in resolves /faq to the signed faq.html',
  navIn(flatOn, `${ORIGIN}/faq`).outcome === 'CHECK' &&
    navIn(flatOn, `${ORIGIN}/faq`).entry.path === '/faq.html',
);
check(
  'the fallback is for navigations only, never subresources',
  navIn(flatOn, `${ORIGIN}/faq`, 'script').outcome === 'BLOCK_UNMANIFESTED',
);
check(
  'an exact match still wins over the fallback',
  navIn(flatOn, `${ORIGIN}/index.html`).entry.path === '/index.html',
);
check(
  'the fallback is not recursive: /a does not become /a/index.html',
  navIn(
    { scope: { include: ['/'], exclude: [], html_extension: true }, assets: [{ path: '/a/index.html', sha256: 'x', sha384: 'y', size: 1, content_type: 'text/html' }] },
    `${ORIGIN}/a`,
  ).outcome === 'PASSTHROUGH',
);
check(
  'a manifest with no scope object is treated as opt-out',
  decideRequest({ url: `${ORIGIN}/faq`, origin: ORIGIN, destination: 'document', manifestState: 'VALID', manifest: { assets: flatAssets } })
    .outcome === 'PASSTHROUGH',
);

console.log('\nhard manifest states block everything in scope');
for (const state of ['TAMPERED', 'ROLLBACK', 'UNTRUSTED_ROOT', 'UNSUPPORTED']) {
  check(
    `${state} blocks`,
    req(`${ORIGIN}/assets/app.js`, { manifestState: state }).outcome === 'BLOCK_TAMPER' &&
      isHardFailure(state),
  );
  check(
    `${state} still lets the manifest itself be fetched`,
    req(`${ORIGIN}/veil-guard-manifest.json`, { manifestState: state }).outcome === 'PASSTHROUGH',
    'otherwise a recovered deployment could never be re-read',
  );
}

console.log('\ncold worker with no manifest yet');
// Regression. A Service Worker is terminated whenever the browser chooses, and its
// module state goes with it; `install` and `activate` do not fire again on restart.
// This path used to return PASSTHROUGH, so every request arriving at a restarted
// worker was served unverified — found by running Tier 1 in a real browser, which
// no amount of stubbing had surfaced.
const cold = (url) =>
  decideRequest({ url, origin: ORIGIN, manifestState: 'NETWORK_FAIL', manifest: null });
check(
  'an in-scope request fails closed, it does not pass through',
  cold(`${ORIGIN}/assets/app.js`).outcome === 'BLOCK_NO_MANIFEST',
);
check(
  'the control plane stays reachable, or the worker could never recover',
  cold(`${ORIGIN}/veil-guard-manifest.json`).outcome === 'PASSTHROUGH',
);
check(
  'cross-origin is still none of our business',
  cold('https://cdn.other/x.js').outcome === 'PASSTHROUGH',
);
check(
  'it is reported as unavailability, never as tampering',
  cold(`${ORIGIN}/assets/app.js`).outcome !== 'BLOCK_TAMPER',
);

console.log('\nresponse decisions (SPEC §8.3, §7.2, §7.3)');
const ok = { entry, status: 200, redirected: false, contentType: 'text/javascript', digestHex: 'aa', byteLength: 10 };
check('matching response is served', decideResponse(ok).outcome === 'SERVE_VERIFIED');
check(
  'hash mismatch blocks',
  decideResponse({ ...ok, digestHex: 'ff' }).outcome === 'BLOCK_TAMPER',
);
check('size mismatch blocks', decideResponse({ ...ok, byteLength: 11 }).outcome === 'BLOCK_TAMPER');
check(
  'a redirected subresource blocks',
  decideResponse({ ...ok, redirected: true }).outcome === 'BLOCK_TAMPER',
);
check(
  '206 is out of scope for verification, not a failure',
  decideResponse({ ...ok, status: 206 }).outcome === 'PASSTHROUGH',
);
check(
  'a 5xx is a network failure, never tampering',
  decideResponse({ ...ok, status: 503 }).outcome === 'NETWORK_FAIL',
);
check(
  'content-type equivalence is honoured',
  decideResponse({ ...ok, contentType: 'application/javascript; charset=utf-8' }).outcome ===
    'SERVE_VERIFIED',
);
check(
  'a different content type blocks',
  decideResponse({ ...ok, contentType: 'text/html' }).outcome === 'BLOCK_TAMPER',
);

console.log('\npresentation (SPEC §8.2)');
check('a network failure is never the security overlay', presentationFor('NETWORK_FAIL').ui === 'retry');
check('expiry is a quiet notice', presentationFor('EXPIRED').ui === 'notice' && !presentationFor('EXPIRED').blocking);
check('tampering is blocking', presentationFor('TAMPERED').blocking === true);
check('unsupported gets its own message', presentationFor('UNSUPPORTED').ui === 'unsupported');
check('valid shows nothing', presentationFor('VALID').ui === 'none');

console.log('\npinning (trust on first use)');
check(
  'first run adopts the baked-in root',
  pinTransition({ pin: null, manifestVersion: 100, trustRootIdHex: 'aa' }).action === 'adopt',
);
check(
  'a newer version advances the pin',
  pinTransition({ pin: { trustRootId: 'aa', version: 100 }, manifestVersion: 101, trustRootIdHex: 'aa' })
    .action === 'advance',
);
check(
  're-reading the same manifest changes nothing',
  pinTransition({ pin: { trustRootId: 'aa', version: 100 }, manifestVersion: 100, trustRootIdHex: 'aa' })
    .action === 'unchanged',
);
check(
  'an older version is a rollback',
  pinTransition({ pin: { trustRootId: 'aa', version: 100 }, manifestVersion: 99, trustRootIdHex: 'aa' })
    .reason === 'rollback',
);
check(
  'a changed root without a rotation is rejected',
  pinTransition({ pin: { trustRootId: 'aa', version: 100 }, manifestVersion: 100, trustRootIdHex: 'bb' })
    .reason === 'trust-root-changed-without-rotation',
  'otherwise replacing sw.js would replace the anchor',
);

console.log('\nrotation chains (SPEC §9.1)');
{
  const payload = unhex(V.rotation.payload_utf8_hex);
  const bundle = unhex(V.rotation.bundle_hex);
  const pinnedRoot = JSON.parse(new TextDecoder().decode(unhex(V.manifest.payload_utf8_hex))).trust_root;
  const pin = { trustRootId: V.derivations.trust_root.expect_trust_root_id, version: 0, rotationVersion: 0 };

  const once = await applyRotationChain({
    pin,
    pinnedRoot,
    fetchStatement: (i) => (i === 0 ? { payload, bundle } : null),
  });
  check('a valid single-link chain is applied', once.ok && once.applied.length === 1);
  check(
    'the pin moves to the new root',
    once.pin.trustRootId === V.rotation.expect_new_trust_root_id,
  );

  // The same statement offered twice: the second application must fail, because a
  // rotation's version must be strictly greater than the one already pinned.
  const replayed = await applyRotationChain({
    pin,
    pinnedRoot,
    fetchStatement: () => ({ payload, bundle }),
  });
  check(
    'a repeated statement stops the chain rather than looping',
    !replayed.ok && replayed.reason === 'rotation-rejected',
  );

  let served = 0;
  const capped = await applyRotationChain({
    pin,
    pinnedRoot,
    fetchStatement: () => {
      served++;
      return { payload: new Uint8Array([1]), bundle: new Uint8Array([2]) };
    },
  });
  check(
    'a hostile endless chain is bounded',
    !capped.ok && served <= MAX_ROTATION_CHAIN,
    `served ${served}`,
  );

  const none = await applyRotationChain({ pin, pinnedRoot, fetchStatement: () => null });
  check('no statements means no change', none.ok && none.applied.length === 0);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
