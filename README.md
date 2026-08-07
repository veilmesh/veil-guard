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

```bash
cargo install --path .
```

### 2. Generate Keypair (2-of-3 Threshold)

```bash
veil-guard keygen --out-dir .keys
```

### 3. Sign Web Build Directory

```bash
veil-guard sign --dist ./dist --key-file .keys/veil-guard.key
```

### 4. Verify Local Build

```bash
veil-guard verify --dist ./dist --pubkey-file .keys/veil-guard.pub
```

### 5. Run Out-of-Band Remote Audit

```bash
veil-guard audit --url https://app.veilmesh.com --pubkey-file .keys/veil-guard.pub
```

---

## 📄 Protocol Specification

See [`SPEC.md`](./SPEC.md) for the normative specification of binary containers (`VGSIG1`), domain separation prefixes (RFC 6962), WebCrypto key encodings, verifier state machines, and path canonicalization rules.

---

## 🧪 Testing & Conformance

`veil-guard` features a frozen cross-language test vector suite:

```bash
# Run Rust test suite
cargo test

# Run JS WebCrypto verifier against conformance vectors
node testdata/verify_vectors.mjs
```

---

## 📜 License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE).
