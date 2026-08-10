# veil-guard

> **Zero-Trust Web Asset Integrity & Attestation Suite for Modern SPAs and WebAssembly**

`veil-guard` brings iOS/Android App Store-style code signing guarantees to Single Page Applications (SPAs), WebAssembly modules, and privacy-focused web applications — without blockchains, heavy browser extensions, or vendor lock-in.

---

## 🛡️ Honest Threat Model & Security Boundaries

`veil-guard` establishes an explicit, audited threat model. It differentiates between **Subresource / CDN Tampering** (handled via SRI & Service Worker) and **Origin Server Compromise** (handled via Out-of-Band CLI Audit, Rekor Transparency, or Extension).

| Attack Scenario | Threat Level | Tier 0 (CLI / SRI / CSP / Rekor) | Tier 1 (Service Worker) | Tier 2 (Extension) |
| :--- | :---: | :---: | :---: | :---: |
| **CDN Subresource Compromise** (HTML-linked CSS/JS) | High | ✅ Blocked via SRI | ✅ Blocked | ✅ Blocked |
| **Dynamic Lazy Route / Wasm Chunk Tampering** (import()) | High | ⚠️ Requires SW / Import Map | ✅ Blocked via SW | ✅ Blocked |
| **Post-First-Visit External Script Injection** | High | ⚠️ Partial (CSP) | ✅ Blocked via SW | ✅ Blocked |
| **Post-First-Visit Inline Script Injection** | High | ✅ Blocked via CSP Hash / Nonce | ❌ Unseen by SW `fetch` | ✅ Blocked |
| **Accidental / Corrupted Deploy** | Medium | ✅ Blocked via SRI | ✅ Blocked via SW | ✅ Blocked |
| **Initial Origin Compromise** (Evil HTML served on 1st visit) | Critical | ⚠️ Detectable via Out-of-Band CLI Audit | ❌ (SW not installed) | ✅ Blocked |
| **Origin Compromise via Evil `sw.js` Replacement** | Critical | ⚠️ Detectable via Out-of-Band CLI Audit | ❌ (SW replaced) | ✅ Blocked |
| **Signer Private Key Misuse / Theft** | Critical | ⚠️ Detectable via Rekor & Keyless OIDC | ⚠️ Detectable | ⚠️ Detectable |
| **Targeted Malicious Delivery** (Selective bad bundle) | Critical | ⚠️ Detectable via Multi-Region `veil-guard diff` | ❌ | ⚠️ Detectable |

> **Prior Art Acknowledgments:** `veil-guard` draws architectural inspiration from **Meta Code Verify** (WhatsApp Web / Cloudflare) and **WEBCAT** (Freedom of the Press Foundation).

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
|  4. Key Rotation & Revocation: Chain-of-Trust signed statements                    |
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
|                      TIER 2: Out-of-Band Browser Extension                         |
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
