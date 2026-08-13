# veil-guard

> **Zero-Trust Web Asset Integrity & Attestation Suite for Modern SPAs and WebAssembly**

`veil-guard` brings iOS/Android App Store-style code signing guarantees to Single Page Applications (SPAs), WebAssembly modules, and privacy-focused web applications — without blockchains, heavy browser extensions, or vendor lock-in.

---

## 🛡️ Honest Threat Model & Security Boundaries

`veil-guard` distinguishes **Subresource / CDN Tampering** (handled by SRI and the
Service Worker) from **Origin Server Compromise** (handled, only partially, by the
out-of-band CLI audit).

Every cell below describes code in this repository, and the words are chosen
carefully. **Blocked** means the attack does not reach the page. **Detected** means it
reaches the page and something tells you afterwards — an icon, a finding, an alert.
The two are not interchangeable, and a threat model that blurs them is worse than none.

| Attack Scenario | Level | Tier 0 (CLI / SRI / CSP / audit) | Tier 1 (Service Worker) | Tier 2 (extension) |
| :--- | :---: | :---: | :---: | :---: |
| **CDN Subresource Compromise** (HTML-linked CSS/JS) | High | ✅ Blocked via SRI | ✅ Blocked | ✅ Blocked (via Tier 1) |
| **Dynamic Lazy Route / Wasm Chunk Tampering** (`import()`) | High | ❌ No SRI to apply | ✅ Blocked via SW | ✅ Blocked (via Tier 1) |
| **Post-First-Visit External Script Injection** | High | ⚠️ Partial (CSP) | ✅ Blocked via SW | ✅ Blocked (via Tier 1) |
| **Post-First-Visit Inline Script Injection** | High | ✅ Blocked via CSP hash | ❌ Unseen by SW `fetch` | ❌ Same |
| **Accidental / Corrupted Deploy** | Medium | ✅ Blocked via SRI | ✅ Blocked via SW | ✅ Blocked |
| **Initial Origin Compromise** (evil HTML on 1st visit) | Critical | ⚠️ Detected after the fact via `audit` | ❌ SW not installed yet | 🦊 Blocked on Firefox · ⚠️ Detected on Chrome |
| **Origin Compromise via Evil `sw.js` Replacement** | Critical | ⚠️ Detected after the fact via `audit` | ❌ SW replaced | ⚠️ Detected, then the origin is blocked |
| **`Clear-Site-Data` evicts the worker** | High | ❌ | ❌ SW cleared | ⚠️ Detected |
| **Signer Private Key Theft** | Critical | ⚠️ One key is not enough: 2-of-3 threshold (§4.4) | ⚠️ Same | ✅ Revocable out-of-band (§9.2) |
| **Threshold of Signer Keys Stolen** | Critical | ❌ Indistinguishable from a legitimate build | ❌ Same | ❌ Same — rotate, do not revoke |
| **Targeted Malicious Delivery** (bad bundle to some visitors) | Critical | ⚠️ Detected via multi-vantage `audit` + `diff` | ❌ | ⚠️ Detected |

Two entries need their footnotes read.

**Firefox blocks the first visit; Chrome cannot.** `webRequest.filterResponseData`
lets the extension buffer a response, hash it, and refuse to release a single byte if
the digest is wrong. Chrome's MV3 has no equivalent — `declarativeNetRequest` never
sees a response body — so there the extension verifies the worker file out-of-band,
raises an interstitial and blocks the origin going forward. That is detection followed
by containment, not prevention, and the table says so.

**"Detected, then the origin is blocked"** means the extension's background worker
fetches `veil-guard-sw.js` itself, outside any page's Service Worker, compares it with
the signed manifest, and on a mismatch adds a blocking rule for the origin, posts a
system notification and redirects the tab to an interstitial. The page that already
loaded is not un-loaded.

### What is deliberately still absent

- **Keyless / OIDC signing (Fulcio).** Identities are long-lived keys today. Short-lived
  certificates tied to a workload identity would remove the standing key entirely.
- **Reproducible builds.** The manifest's `source` block is a claim by the signer, not
  a proof that the bytes came from any particular tree (`SPEC.md` §1).
- **Cryptographic Rekor verification.** `audit --rekor-lookup` re-reads a published
  entry and compares the hash; it does **not** verify the log's signed entry timestamp
  or an inclusion proof, so the guarantee is only as good as the endpoint answering.
  Called out again under [Transparency log](#-transparency-log-rekor) below.

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
|  4. Key Rotation & Revocation: Chain-of-Trust signed statements (§9.1, §9.2)       |
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
|                      TIER 2: Out-of-Band Browser Extension                          |
|                                                                                     |
|  MV3 extension (veilmesh/veil-guard-ext), Chrome 111+ / Firefox 128+:               |
|  1. Trust root from a bundled registry, MDM policy or a federated feed — never      |
|     from the origin being checked. First-visit pinning is shown as TOFU, not green. |
|  2. Background verification of veil-guard-sw.js, fetched outside any page worker    |
|  3. Out-of-band revocation (§9.2), the one mechanism SPEC assigns to this tier      |
|  4. Firefox: response bodies verified before release (filterResponseData)           |
|  5. Chrome: detection, then a blocking rule for the origin and an interstitial      |
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

Remote signing through AWS or GCP KMS is a second flag, and it is not in the
default build either. `kms` pulls `aws-lc-sys` — C and assembly, built through
cmake and bindgen — taking the dependency tree from 167 crates to 916 and the
binary from 4.4 MB to 23 MB. Nobody who signs with local key files should carry
that:

```bash
cargo install --path . --features audit,kms
```

#### Prebuilt binaries

Release archives come in two flavours. The plain ones are `--features audit` and
**do not** understand `--kms-key-id`; asking them to use it produces
`KMS support is disabled`. The `-kms` archives do.

| Archive | Contents |
|---|---|
| `veil-guard-<ver>-x86_64-unknown-linux-musl` | base; static, runs on Alpine |
| `veil-guard-<ver>-aarch64-unknown-linux-musl` | base |
| `veil-guard-<ver>-x86_64-apple-darwin` | base |
| `veil-guard-<ver>-aarch64-apple-darwin` | base |
| `veil-guard-<ver>-x86_64-pc-windows-msvc` | base |
| `veil-guard-<ver>-x86_64-unknown-linux-gnu-kms` | **with KMS**, glibc — for CI runners |
| `veil-guard-<ver>-aarch64-apple-darwin-kms` | **with KMS** — for signing by hand on Apple Silicon |

The KMS builds are glibc and native-only because `aws-lc-sys` does not
cross-compile to musl. On any other platform, build from source with the flag
above.

### 2. Generate signer identities

One signer is one Ed25519 keypair *and* one P-256 keypair, bound together by a key
ID (SPEC §4.1). Each `keygen` writes `<name>.key.json` (private, mode 0600,
**unencrypted**) and `<name>.pub.json`.

A `recovery` key exists to survive the compromise of a build machine, so it must
never be stored on one.

To keep a signer's P-256 half in a cloud KMS instead, import its public key. Both
clouds hand back DER SubjectPublicKeyInfo; `keygen` converts it to the uncompressed
SEC1 point the trust root needs, generates the Ed25519 half locally, and records the
KMS key **in the signer's own file** — so a threshold can have several remote
signers, each with its own key:

```bash
aws kms get-public-key --key-id "$ARN" --query PublicKey --output text | base64 -d > p256.der
```

```bash
veil-guard keygen --out-dir .keys --name ci-1 --p256-public-der p256.der --kms-key-id "$ARN"
```

`sign` then needs no KMS arguments at all — each key file says where its half lives.
This is half a measure and the tool says so: the Ed25519 seed is still on disk. See
SPEC §4.6 for what is and is not achieved.

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

## 🔎 Transparency log (Rekor)

`sign --rekor-upload` publishes the manifest hash and signature to a Sigstore Rekor
instance and records the returned log index in `source.rekor`.
`audit --rekor-lookup` reads that index back and checks the recorded hash matches.

**Read the name of the flag literally.** It is a lookup:

- ✅ It proves the hash was published, and that the endpoint you asked still reports
  the same one. That is enough to notice a manifest quietly swapped after the fact.
- ❌ It does **not** verify the log's signed entry timestamp, does not check an
  inclusion proof against a signed tree head, and does not pin the log's public key.

Which means the answer is worth exactly as much as the endpoint at `--rekor-url`.
Anyone who can redirect that URL, or sit on the network path, can fabricate the whole
reply. Against an attacker, this is not yet a transparency guarantee — it is a
publication record. Closing that gap is tracked in [`ROADMAP.md`](./ROADMAP.md); it
needs SET verification with a pinned log key, and inclusion-proof checking against a
checkpoint.

The finding the auditor emits says the same thing, so nobody reading a report has to
come back here for it.

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
