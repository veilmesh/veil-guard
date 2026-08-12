# veil-guard

> **Zero-Trust Web Asset Integrity & Attestation Suite for Modern SPAs and WebAssembly**

`veil-guard` brings iOS/Android App Store-style code signing guarantees to Single Page Applications (SPAs), WebAssembly modules, and privacy-focused web applications — without blockchains, heavy browser extensions, or vendor lock-in.

---

## 🛡️ Honest Threat Model & Security Boundaries

`veil-guard` distinguishes **Subresource / CDN Tampering** (handled by SRI and the
Service Worker) from **Origin Server Compromise** (handled, only partially, by the
out-of-band CLI audit).

Everything in this table describes code that exists in this repository today. Tier 2,
transparency-log publication and keyless signing are **not built** — they are tracked
in [`ROADMAP.md`](./ROADMAP.md) and are deliberately absent from the columns below,
because a threat model that credits unwritten code is worse than no threat model.

| Attack Scenario | Threat Level | Tier 0 (CLI / SRI / CSP / audit) | Tier 1 (Service Worker) |
| :--- | :---: | :---: | :---: |
| **CDN Subresource Compromise** (HTML-linked CSS/JS) | High | ✅ Blocked via SRI | ✅ Blocked |
| **Dynamic Lazy Route / Wasm Chunk Tampering** (`import()`) | High | ❌ No SRI to apply | ✅ Blocked via SW |
| **Post-First-Visit External Script Injection** | High | ⚠️ Partial (CSP) | ✅ Blocked via SW |
| **Post-First-Visit Inline Script Injection** | High | ✅ Blocked via CSP hash | ❌ Unseen by SW `fetch` |
| **Accidental / Corrupted Deploy** | Medium | ✅ Blocked via SRI | ✅ Blocked via SW |
| **Initial Origin Compromise** (evil HTML on 1st visit) | Critical | ⚠️ Detectable after the fact via `audit` | ❌ SW not installed yet |
| **Origin Compromise via Evil `sw.js` Replacement** | Critical | ⚠️ Detectable after the fact via `audit` | ❌ SW replaced |
| **Signer Private Key Theft** | Critical | ⚠️ One key is not enough: 2-of-3 threshold (§4.4) | ⚠️ Same |
| **Threshold of Signer Keys Stolen** | Critical | ❌ Indistinguishable from a legitimate build | ❌ Same |
| **Targeted Malicious Delivery** (bad bundle to some visitors) | Critical | ⚠️ Detectable via multi-vantage `audit` + `diff` | ❌ |

"Detectable after the fact" means exactly that: the attack succeeds against whoever
loads the page, and `veil-guard audit` tells you afterwards — if you are running it.
It is not prevention.

### Not built yet

Named here because they appear in the architecture diagram, the roadmap, and the
prior art, and their absence changes what the tool protects:

- **Tier 2 browser extension.** The only design that can cover the first visit and a
  replaced Service Worker. Until it ships, both rows above stay `❌ / ⚠️`.
- **Transparency log publication (Rekor) and keyless OIDC signing.** Would make a
  stolen-key signature publicly discoverable. Nothing in this repo talks to a log.

> **Prior Art Acknowledgments:** `veil-guard` draws architectural inspiration from **Meta Code Verify** (WhatsApp Web / Cloudflare) and **WEBCAT** (Freedom of the Press Foundation). Both implement the Tier 2 extension that this project has not built.

---

## 🏗️ Architectural Overview

```
+------------------------------------------------------------------------------------+
|                         TIER 0: Build-Time & CLI Engine                            |
|                                                                                    |
|  Rust CLI (veil-guard-cli):                                                        |
|  1. NFC Unicode & Path Normalization (macOS NFD -> NFC, Windows '\' -> '/')        |
|  2. Binary Hashing: SHA-256 (Manifest/CSP) & SHA-384 (SRI)                         |
|  3. Monotonic Build Unix-Timestamp Versioning & Expiry                             |
|  4. Key Rotation: Chain-of-Trust signed statements (revocation: SPEC only)         |
|  5. Dual Signing: Ed25519 (verify_strict) AND ECDSA P-256 (WebCrypto)              |
|  6. Multi-Page HTML SRI Injection & Per-Page CSP Hash Generators                   |
|  7. Config Generators: Integrity-Policy & Server Headers (Nginx/Caddy/Netlify)     |
|  8. Out-of-Band Remote Auditor & Multi-Region Diff Engine                          |
+------------------------------------------------------------------------------------+
                                          |
                                          v
+------------------------------------------------------------------------------------+
|                      TIER 1: Browser Service Worker Runtime                        |
|                                                                                    |
|  Service Worker Runtime (veil-guard-sw.js):                                        |
|  1. Key & Version Chain-of-Trust Pinning in IndexedDB                              |
|  2. Binary ArrayBuffer Signature Validation (ECDSA P-256 / Ed25519 WebCrypto)      |
|  3. Cache Storage Strategy: Verify -> Cache by SHA-256 -> Serve                     |
|  4. Scope-Restricted Subresource Enforcement for Dynamic import() & WASM Chunks    |
+------------------------------------------------------------------------------------+
                                          |
                                          v
+------------------------------------------------------------------------------------+
|            TIER 2: Out-of-Band Browser Extension  — NOT BUILT (ROADMAP §3)          |
+------------------------------------------------------------------------------------+
```

---

## 🚀 Quickstart

### 1. Installation

The out-of-band auditor reaches the network, so it is kept behind a feature flag:
the default build is small enough to review, and nothing that signs can also fetch.
Install with `--features audit` on the machine that runs audits — not on the one
that holds signing keys.

```bash
cargo install --path . --features audit
```

### 2. Generate signer identities

One signer is one Ed25519 keypair *and* one P-256 keypair, bound together by a key
ID (SPEC §4.1). Each `keygen` writes `<name>.key.json` (private, mode 0600,
**unencrypted**) and `<name>.pub.json`.

A `recovery` key exists to survive the compromise of a build machine, so it must
never be stored on one.

```bash
veil-guard keygen --out-dir .keys --name alice
```

```bash
veil-guard keygen --out-dir .keys --name bob
```

```bash
veil-guard keygen --out-dir .keys --name carol --role recovery
```

### 3. Assemble the trust root (2-of-3)

The trust root is what clients pin. Build it from the *public* halves; its ID is a
hash over a binary encoding, so it never depends on JSON formatting (SPEC §4.5).

```bash
veil-guard trust-root --key .keys/alice.pub.json --key .keys/bob.pub.json --key .keys/carol.pub.json --threshold 2 --out trust-root.json
```

### 4. Emit the Tier 1 runtime

Writes a self-contained Service Worker with the trust root baked in, plus the
page-side loader. Point `--out` at the directory your bundler copies verbatim
(`public/` for Vite) so the worker lands at the site root and can claim scope `/`.
Re-run this only when the trust root changes, not on every build.

```bash
veil-guard runtime --trust-root trust-root.json --out public
```

Then load it from every page, ideally as the first script:

```html
<script src="/veil-guard-loader.js"></script>
```

### 5. Build, then sign

`sign` must run **after** the bundler, against the build output — it rewrites the
HTML in place to add `integrity` attributes, and hashes the result (SPEC §10).

Scope is the whole origin, so the worker refuses every same-origin request that is
not a signed file. Dynamic endpoints have no file to sign and must be carved out
with `--exclude`, or those calls will be blocked.

```bash
npm run build && veil-guard sign --dist ./dist --trust-root trust-root.json --key .keys/alice.key.json --key .keys/bob.key.json --exclude /api/ --headers-out ./headers
```

`--headers-out` writes `_headers`, `veil-guard.nginx.conf` and
`veil-guard.Caddyfile` with per-page CSP inline-script hashes and a report-only
`Integrity-Policy`. Add `--enforce-headers` only once `audit` reports no
missing-integrity findings.

If your generator emits flat files — `/faq` served from `faq.html`, which is what
vite-ssg, Astro and Hugo do by default — add `--navigation-html-fallback`. Without it
those documents match no manifest entry and the worker passes them through
unverified. Check first that the host really maps `/faq` to `faq.html`: under a
single-page-app fallback it answers with `index.html` instead, and the worker would
compare those bytes against `faq.html` and block a healthy deployment (SPEC §7.1.1).

Inline scripts are hashed from the built page, but a host that an inline bootstrap
goes on to *inject* from appears nowhere in `dist` and has to be named, or the
generated policy will block it. A tag manager is exactly this shape:

```bash
veil-guard sign --dist ./dist --trust-root trust-root.json --key .keys/alice.key.json --key .keys/bob.key.json --csp-source https://www.googletagmanager.com --headers-out ./headers
```

### 6. Verify the local build

```bash
veil-guard verify --dist ./dist --trust-root trust-root.json
```

### 7. Run an out-of-band remote audit

The trust root is read from this local file and never from the audited site — that
is the whole point of the command. Give each vantage point a `--label` and keep the
snapshots: divergence between them is the only signal that reveals a bundle served
to some visitors and not others.

```bash
veil-guard audit --url https://app.veilmesh.com --trust-root trust-root.json --label eu-west --out snapshots/eu-west.json
```

```bash
veil-guard diff snapshots/eu-west.json snapshots/us-east.json
```

### Rotating the trust root

A rotation statement moves clients that *already* trust the old root. It is not a
revocation — see SPEC §9.2 for why a compromised origin cannot be made to deliver
one.

```bash
veil-guard rotate --from trust-root.json --to trust-root-next.json --key .keys/alice.key.json --key .keys/bob.key.json --out dist/veil-guard-rotation.json
```

---

## 🤖 CI/CD & Cloud KMS Integrations

We provide first-class integrations to automate manifest signing, build-provenance embedding, and key management inside CI/CD environments.

### 1. Node.js Wrapper (`@veilmesh/veil-guard`)
A TypeScript/ESModule wrapper over the CLI binary. It automatically detects CI environments (GitHub Actions, GitLab CI) to extract and embed **SLSA Provenance** metadata.

```bash
npm install --save-dev @veilmesh/veil-guard
```

```typescript
import { sign } from '@veilmesh/veil-guard';

await sign({
  dist: './dist',
  trustRoot: './trust-root.json',
  keys: ['.keys/alice.key.json'],
  // Auto-detects and embeds GITHUB_SHA/CI_COMMIT_SHA + SLSA metadata by default
  embedProvenance: true, 
  // KMS Integration (signs P-256 via Cloud HSM, Ed25519 locally)
  kms: {
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/my-key-uuid',
    provider: 'aws',
  }
});
```

### 2. Vite Plugin (`vite-plugin-veil-guard`)
Automatically hooks into the Rollup `closeBundle` phase to scan and sign the generated build.

```bash
npm install --save-dev vite-plugin-veil-guard
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import { veilGuardPlugin } from 'vite-plugin-veil-guard';

export default defineConfig({
  plugins: [
    veilGuardPlugin({
      trustRootPath: './trust-root.json',
      keyPath: ['.keys/alice.key.json'], // Local Ed25519 seed key file
      exclude: ['/api/'],
      kms: {
        keyId: 'projects/my-gcp-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key',
        provider: 'gcp',
      }
    }),
  ],
});
```

### 3. GitHub Action (`veilmesh/veil-guard-action`)
Automates installation and signing inside GitHub Actions pipelines.

```yaml
- name: Sign Assets c veil-guard
  uses: veilmesh/veil-guard-action@v1
  with:
    dist: 'dist'
    trust-root: 'trust-root.json'
    keys: '.keys/alice.key.json'
    exclude: |
      /api/
      /ws/
    kms-key-id: 'arn:aws:kms:us-east-1:123456789012:key/my-key-uuid'
    kms-provider: 'aws'
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

---

## 📄 Protocol Specification

See [`SPEC.md`](./SPEC.md) for the normative specification of binary containers (`VGSIG1`), domain separation prefixes (RFC 6962), WebCrypto key encodings, verifier state machines, and path canonicalization rules.

---

## 🧪 Testing & Conformance

`testdata/conformance_vectors.json` is the executable form of `SPEC.md`, and it is
frozen: P-256 signing is randomized, so regenerating it produces different — equally
valid — signatures and destroys the cross-implementation meaning of the suite. Both
implementations are held to the same file.

```bash
cargo test --all-targets --features audit
```

```bash
node testdata/verify_vectors.mjs
```

```bash
node testdata/verify_policy.mjs
```

The two remaining scripts consume output the CLI just produced, rather than fixtures
— they are the Rust-signs / JavaScript-verifies direction:

```bash
node testdata/verify_manifest.mjs ./dist trust-root.json VALID
```

```bash
node testdata/run_sw_smoke.mjs public/veil-guard-sw.js
```

CI runs all of the above, plus lints and an end-to-end sign → cross-verify → tamper
round trip. See [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

---

## 📜 License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).
