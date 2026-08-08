# veil-guard Protocol Specification

**Spec version:** `veil-guard/1`
**Status:** Draft — normative for implementations in this repository.
**License:** MIT OR Apache-2.0

This document is the single source of truth for the `veil-guard` wire formats. Two
independent implementations exist (Rust CLI, JavaScript Service Worker); where this
document and an implementation disagree, this document wins and the implementation is
buggy. Test vectors in `testdata/conformance_vectors.json` are generated from, and
checked against, this document.

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are used as in RFC 2119.

---

## 1. Scope and non-goals

`veil-guard` binds a set of static web assets to a threshold of signing keys, and lets
three different verifiers (a build-time CLI, an out-of-band auditor, a browser Service
Worker) check that binding.

**In scope:** asset↔hash binding, detached threshold signatures, key rotation,
rollback resistance, path canonicalization.

**Explicitly not in scope** (see `README.md` threat model):

- Protecting the *first* visit to a compromised origin. Nothing in this protocol can;
  Tier 0 (out-of-band audit) and Tier 2 (extension) address it.
- Protecting against replacement of the Service Worker itself by a compromised origin.
- Proving that the signed bytes correspond to any particular source tree. The
  `source` block (§6.6) is a *claim by the signer*, not a proof. Closing that gap
  requires reproducible builds and is out of scope for v1.

---

## 2. Primitives and encodings

| Name | Definition |
|---|---|
| `SHA-256` | FIPS 180-4, 32-byte output |
| `SHA-384` | FIPS 180-4, 48-byte output. Used **only** for SRI attributes. |
| `ed25519` | RFC 8032 Ed25519ph=off, pure Ed25519. Verification **MUST** be strict (§4.3). |
| `p256` | ECDSA over NIST P-256 with SHA-256 (FIPS 186-4) |

**Hex** in JSON means lowercase, unpadded-per-byte, no `0x` prefix, `[0-9a-f]*` with
even length. Implementations **MUST** reject uppercase and non-hex characters rather
than normalizing them.

**Base64** appears only inside SRI attribute values (`sha384-<base64>`), standard
alphabet with `=` padding, as required by the SRI specification.

**Integers** in JSON are unsigned and **MUST** be within `[0, 2^53-1]` so that
JavaScript can represent them exactly. Implementations **MUST** reject values outside
this range, including negative values and floats.

### 2.1 Binary key encodings

| Algorithm | Public key | Signature |
|---|---|---|
| `ed25519` | raw 32 bytes | raw 64 bytes (`R‖S`) |
| `p256` | SEC1 **uncompressed**, 65 bytes: `0x04 ‖ X(32) ‖ Y(32)` | raw **`r‖s`**, 64 bytes |

> **Implementation note — the single most likely interop bug.** WebCrypto's
> `ECDSA` verify accepts **only** raw `r‖s`. The Rust `p256`/`ecdsa` crates expose both
> `Signature::to_bytes()` (raw `r‖s` — correct here) and `Signature::to_der()`
> (ASN.1 — **wrong** here). Likewise `crypto.subtle.importKey("raw", …)` for
> `ECDSA`/`P-256` expects the 65-byte uncompressed SEC1 point, not DER
> `SubjectPublicKeyInfo`. The conformance vectors pin both encodings explicitly.

Compressed SEC1 points (`0x02`/`0x03` prefix) **MUST** be rejected on input. P-256
signatures with `r` or `s` equal to zero, or greater than or equal to the curve order,
**MUST** be rejected. Rejecting high-`s` signatures is *not* required: ECDSA signature
malleability does not matter here, because a signature is never used as an identifier
or a deduplication key in this protocol.

---

## 3. Domain separation

Every hash and every signature in this protocol is computed over a domain-separated
input. The prefix is the ASCII label followed by a single `0x00` byte.

| Purpose | Prefix (ASCII, then `0x00`) |
|---|---|
| Manifest signature | `veil-guard/manifest/v1` |
| Rotation statement signature | `veil-guard/rotation/v1` |
| Revocation statement signature | `veil-guard/revocation/v1` |
| Key identity hash | `veil-guard/keyid/v1` |
| Trust root hash | `veil-guard/trustroot/v1` |

```
SIG_INPUT = PREFIX ‖ 0x00 ‖ payload_bytes
```

Implementations **MUST NOT** provide an API that signs or verifies without a prefix.
A signature produced under one prefix **MUST NOT** verify under another; the
conformance suite contains a negative vector for exactly this.

---

## 4. Keys, identity, and the trust root

### 4.1 A key is a pair of keypairs

A `veil-guard` **signer** holds one Ed25519 keypair *and* one P-256 keypair. The two
are bound together into a single identity by the key ID. There is no notion of a
signer that only has one algorithm.

### 4.2 Key ID

```
key_id = SHA-256( "veil-guard/keyid/v1" ‖ 0x00 ‖ ed25519_pub(32) ‖ p256_pub(65) )[0..8]
```

8 bytes, rendered as 16 lowercase hex characters. Truncation to 8 bytes is
acceptable because `key_id` is a *lookup key within an authenticated trust root*, not
a security boundary: a collision does not let an attacker sign anything. Two keys in
one trust root sharing a `key_id` **MUST** be rejected at construction time.

### 4.3 Strict Ed25519 verification

Rust implementations **MUST** use `ed25519_dalek::VerifyingKey::verify_strict`. This
rejects small-order public keys and non-canonical `R` / `S` encodings, which brings
`dalek` into agreement with WebCrypto's Ed25519 for the edge cases where the RFC 8032
"cofactored vs cofactorless" ambiguity would otherwise let a signature be accepted by
one verifier and rejected by the other.

### 4.4 Trust root

The trust root is the authenticated set of signers and the policy over them.

```json
{
  "threshold": 2,
  "sigalgs": ["ed25519", "p256"],
  "keys": [
    { "key_id": "…16 hex…", "role": "build",    "ed25519": "…64 hex…", "p256": "…130 hex…" },
    { "key_id": "…16 hex…", "role": "build",    "ed25519": "…64 hex…", "p256": "…130 hex…" },
    { "key_id": "…16 hex…", "role": "recovery", "ed25519": "…64 hex…", "p256": "…130 hex…" }
  ]
}
```

Constraints:

- `threshold` **MUST** satisfy `1 <= threshold <= len(keys)` and `len(keys) <= 16`.
- The default deployment profile is **2-of-3**: two `build` keys that live on CI, one
  `recovery` key that **MUST NOT** ever be present on a build machine.
- `sigalgs` **MUST** be a non-empty subset of `["ed25519","p256"]`, listed in that
  canonical order, without duplicates.
- `keys` **MUST** be sorted by `key_id` ascending (bytewise) and contain no duplicates.
- `role` is advisory metadata (`build` | `recovery`); it does not affect verification.

**Rationale for 2-of-3.** A single-key trust root fails in both directions: losing the
key permanently bricks every client that pinned it, and stealing the key lets the thief
issue a rotation that permanently transfers the pin. A threshold root survives the loss
of one key (the remaining build key plus the cold recovery key can still rotate) and
survives the theft of one key (the thief cannot reach the threshold).

### 4.5 Trust root ID

The trust root ID is computed over a **binary** encoding, so it never depends on JSON
canonicalization:

```
sigalg_mask = (0x01 if "ed25519" in sigalgs) | (0x02 if "p256" in sigalgs)

TR_BYTES = u8(threshold)
         ‖ u8(len(keys))
         ‖ u8(sigalg_mask)
         ‖ for each key, ordered by key_id ascending:
               key_id(8) ‖ ed25519_pub(32) ‖ p256_pub(65)

trust_root_id = SHA-256( "veil-guard/trustroot/v1" ‖ 0x00 ‖ TR_BYTES )
```

Full 32 bytes, hex. The manifest carries both `trust_root` and `trust_root_id`; a
verifier **MUST** recompute the ID and reject the manifest on mismatch.

---

## 5. Signature bundle (`veil-guard-manifest.sig`)

Signatures are **detached** and live in a compact binary container. Binary rather than
JSON: the container is parsed *before* anything is verified, so it must have exactly
one valid interpretation.

```
offset  size  field
------  ----  -----------------------------------------------------------
     0     6  magic, ASCII "VGSIG1"
     6     1  format version, 0x01
     7     1  reserved, MUST be 0x00
     8     2  entry_count, u16 little-endian
    10   ...  entry_count × entry
```

Each entry:

```
offset  size  field
------  ----  -----------------------------------------------------------
     0     8  key_id
     8     1  alg_id: 0x01 = ed25519, 0x02 = p256
     9     1  reserved, MUST be 0x00
    10     2  sig_len, u16 little-endian
    12  sig_len  signature bytes
```

Parsing rules — a violation of any of these yields `TAMPERED`, never a warning:

1. Magic, format version, and both reserved fields **MUST** match exactly.
2. `entry_count` **MUST** be in `[1, 64]`.
3. `sig_len` **MUST** equal 64 for both currently defined `alg_id` values. Unknown
   `alg_id` values **MUST** cause the entry to be skipped, not to fail — this is the
   only forward-compatibility hook in the format, and `sig_len` makes skipping
   unambiguous.
4. Entries **MUST** be sorted ascending by `(key_id, alg_id)`.
5. A duplicate `(key_id, alg_id)` pair **MUST** be rejected.
6. There **MUST NOT** be any trailing bytes after the last entry.

---

## 6. Manifest (`veil-guard-manifest.json`)

### 6.1 The signed object is the file, not the JSON

The signature covers the **exact bytes of `veil-guard-manifest.json` as served**. No
canonical-JSON scheme is used, and none is needed. A verifier **MUST**:

1. Read the response body into a byte buffer.
2. Verify signatures over `PREFIX ‖ 0x00 ‖ those bytes` (§5, §7).
3. Only then parse the buffer as JSON.

This ordering is normative. It removes the entire class of bugs where the signer's and
verifier's JSON libraries disagree about key ordering, duplicate keys, Unicode escapes,
or number formatting.

The file **MUST** be UTF-8 without a byte-order mark. It **MUST NOT** contain duplicate
object keys; verifiers **SHOULD** use a parser that rejects them, and **MUST** treat a
duplicate `spec`, `version`, `not_after`, `sigalgs`, `trust_root`, `trust_root_id`, or
`assets` key as `TAMPERED` if their parser surfaces it.

### 6.2 Shape

```json
{
  "spec": "veil-guard/1",
  "version": 1754500000,
  "not_after": 1786036000,
  "sigalgs": ["ed25519", "p256"],
  "trust_root_id": "…64 hex…",
  "trust_root": { "threshold": 2, "sigalgs": ["ed25519","p256"], "keys": [ … ] },
  "scope": {
    "include": ["/"],
    "exclude": ["/api/"]
  },
  "source": {
    "commit": "…",
    "repo": "https://github.com/…",
    "toolchain": { "node": "22.5.1", "vite": "5.4.21", "veil_guard": "0.1.0" }
  },
  "assets": [
    {
      "path": "/assets/index-a1b2c3d4.js",
      "sha256": "…64 hex…",
      "sha384": "…96 hex…",
      "size": 148213,
      "content_type": "text/javascript"
    }
  ]
}
```

### 6.3 Field rules

- `spec` **MUST** be exactly `"veil-guard/1"`.
- `version` is the build's Unix timestamp in seconds (§6.5).
- `not_after` **MUST** be greater than `version`.
- `sigalgs` **MUST** be present and **MUST** equal `trust_root.sigalgs` exactly,
  including order. This is redundant on purpose: the pinned copy inside the trust root
  is authoritative, and the top-level copy exists so a human reading the file sees the
  policy. A mismatch is `TAMPERED`.
- `assets` **MUST** be sorted by `path` ascending, compared bytewise over the
  NFC-normalized UTF-8 encoding. Duplicate paths **MUST** be rejected.
- `sha384` is present so that the out-of-band auditor can cross-check the `integrity`
  attributes it finds in served HTML without re-deriving them. Tier 1 does not use it.

### 6.4 `content_type` comparison

`content_type` stores the **essence** only — media type and subtype, lowercased, with
parameters (`; charset=…`) stripped. Comparison is case-insensitive over the essence,
after mapping through this equivalence table:

| Canonical | Also accepted |
|---|---|
| `text/javascript` | `application/javascript`, `application/x-javascript`, `text/ecmascript`, `application/ecmascript` |
| `application/wasm` | *(none)* |
| `text/css` | *(none)* |
| `application/json` | `text/json` |

A `content_type` mismatch outside these classes is `BLOCK_TAMPER` in Tier 1 and a
reported finding in Tier 0. The byte hash already fixes the content; this check exists
because the same bytes interpreted under a different MIME type can change how the
browser treats them (notably for module scripts, where a non-JavaScript MIME type is
itself a load failure).

### 6.5 Versioning and rollback

`version` is the Unix timestamp, in seconds, of the moment the build was signed. It is
monotonic by construction and requires no state file, which is what makes it safe when
two machines can both sign.

- `--version <N>` and the `SOURCE_DATE_EPOCH` environment variable override the clock,
  in that order of precedence. This exists so the determinism test (§10) can run: two
  invocations of `sign` over an identical tree with the same pinned `version`
  **MUST** produce byte-identical manifest and signature-bundle files.
- **Reverting a bad deploy is a re-build, never a redeploy of the old artifact.** A
  redeployed old manifest carries an old `version` and every client that already saw
  the newer one will reject it as `ROLLBACK`. This is deliberate: it is the same
  mechanism that stops an attacker from replaying a stale, validly-signed manifest that
  contains a known-vulnerable bundle. Deployment tooling **SHOULD** make this loud.

### 6.6 `not_after` is soft

`not_after` bounds how long a client will go on trusting a manifest without
revalidating it. Expiry **MUST NOT** be reported as tampering and **MUST NOT**
fail closed. See `EXPIRED` in §8. The failure mode being avoided is a static site that
has not been redeployed in a year bricking itself for every visitor.

Recommended default: `version + 180 days`.

---

## 7. Path canonicalization

Path handling is where an attacker who controls the server does their work, so the
rules are exhaustive and identical on both sides.

A manifest path is derived from a file's location relative to the `dist` root:

1. Split on the platform separator. On Windows, `\` is a separator; `/` is a separator
   everywhere.
2. Reject if any component is empty, `.`, or `..`.
3. Normalize each component to Unicode **NFC**. This is not optional: macOS APFS hands
   out filenames in NFD, browsers send NFC, and without this step every non-ASCII
   filename silently fails to match.
4. Join with `/` and prepend `/`.
5. The result **MUST NOT** contain `\`, `//`, or a NUL byte.

The CLI **MUST** fail the build if two distinct files normalize to the same path, and
**MUST** fail if two paths differ only by ASCII case — the second check catches trees
that work on a case-insensitive macOS filesystem and break on a case-sensitive server.

Symbolic links **MUST NOT** be followed. A symlink inside `dist` is an error, not a
file to hash.

### 7.1 Deriving the lookup key from a request

A verifier turns a request URL into a manifest key as follows:

1. Take `URL.pathname` — the query string and fragment are **ignored**. Content is
   bound by hash, so a query string cannot smuggle different bytes past the check, and
   ignoring it keeps cache-busting query parameters working.
2. **Reject** — as `BLOCK_TAMPER` — if the raw pathname contains, case-insensitively,
   `%2f`, `%5c`, `%2e%2e`, or `%00`. These are rejected *before* decoding, because
   decoding them would manufacture path structure that was not in the original URL.
3. Percent-decode the remainder, then normalize to NFC.
4. Compare bytewise against `assets[].path`. Comparison is **case-sensitive**.

> **Implementation note — what a URL parser has already done.** A verifier working
> from a WHATWG `URL` does not see the raw pathname. That parser resolves
> percent-encoded dot segments before anything else runs: `/a/%2e%2e/secret.js`
> arrives as `/secret.js`. This is not a gap, because the browser puts that same
> resolved path on the wire, so the verifier and the origin server agree on which
> resource is being requested; the resolved path is then an ordinary lookup, and it
> is refused if nothing signed it. Encoded **separators** are the opposite case —
> `%2F` and `%5C` survive parsing untouched, and a server may still decode them
> into path structure the verifier never saw. Those are the ones step 2 exists for,
> and rejecting them is not optional.
>
> A verifier that works from a raw string instead — the CLI auditor reading an
> `href` out of served markup, for instance — gets no such normalization and must
> apply every rule above itself.

### 7.2 Redirects

Sub-resource fetches issued by the verifier **MUST** use `redirect: "error"`. A server
that answers a request for `/assets/a.js` with a redirect to `/assets/b.js` would
otherwise let the response for one manifest entry be validated against another entry's
hash.

This applies to sub-resources only. Navigation requests keep their `redirect: "manual"`
mode; forcing `error` on them breaks legitimate trailing-slash and locale redirects.
Because a `Request` object's redirect mode cannot be mutated, the Service Worker
**MUST** construct a new `Request` rather than modifying `event.request`.

### 7.3 Range requests

A `206 Partial Content` response cannot be checked against a whole-file hash. Tier 1
**MUST NOT** attempt to verify one; it **MUST** treat a manifested path answered with
`206` as out of scope for verification and **MUST** refuse to serve it from the
verified cache. Media assets that need range requests belong in `scope.exclude`.

---

## 8. Verification

### 8.1 Manifest verification algorithm

Inputs: `payload` (bytes), `bundle` (bytes), `pinned` (trust root from the TOFU pin or
from an out-of-band source), `pinned_version`, `now`.

```
1.  Parse `bundle` per §5.                          → malformed ⇒ TAMPERED
2.  supported ← algorithms this verifier implements
    active    ← pinned.sigalgs ∩ supported
    if active is empty                              ⇒ UNSUPPORTED
3.  qualifying ← 0
    for each key K in pinned.keys:
        present ← { a ∈ active : bundle has entry (K.key_id, a) }
        for each a in present:
            if not verify_a(K.pub_a, sig, PREFIX_manifest ‖ 0x00 ‖ payload)
                                                    ⇒ TAMPERED     (hard fail)
        if present == active:   qualifying += 1
        // present ⊊ active ⇒ K simply does not count
    entries whose key_id is not in pinned.keys are ignored, but reported
4.  if qualifying < pinned.threshold                ⇒ UNTRUSTED_ROOT
5.  parse `payload` as JSON                         → failure ⇒ TAMPERED
6.  if spec ≠ "veil-guard/1"                        ⇒ TAMPERED
    if recompute(trust_root_id) ≠ stated            ⇒ TAMPERED
    if trust_root_id ≠ id(pinned)                   ⇒ UNTRUSTED_ROOT
    if manifest.sigalgs ≠ trust_root.sigalgs        ⇒ TAMPERED
    if any structural rule of §6.3 / §7 is violated ⇒ TAMPERED
7.  if version < pinned_version                     ⇒ ROLLBACK
    (version == pinned_version is fine — re-fetching the same manifest is normal)
8.  if now > not_after                              ⇒ EXPIRED
9.  otherwise                                       ⇒ VALID
```

**Why step 3 is shaped this way.** A present-but-invalid signature is a hard failure,
so an attacker holding only one algorithm's private key for a signer cannot strip the
other algorithm's signature and have that signer still count. An entirely absent
signature merely fails to contribute, which is what lets a verifier that implements
only P-256 still reach the threshold on a manifest that also carries Ed25519.

The residual weakness is honest and worth stating: a verifier that implements only one
of the published algorithms is protected only by that algorithm. That is inherent — it
cannot check what it cannot compute.

### 8.2 States

| State | Class | Tier 1 behaviour | UI |
|---|---|---|---|
| `VALID` | ok | serve verified assets | none |
| `EXPIRED` | soft | serve verified assets; force manifest revalidation on next navigation | quiet warning |
| `NETWORK_FAIL` | soft | serve from verified cache if present; otherwise fail the request | retry banner |
| `TAMPERED` | hard | block every in-scope request | security overlay |
| `ROLLBACK` | hard | block every in-scope request | security overlay |
| `UNTRUSTED_ROOT` | hard | block every in-scope request | security overlay |
| `UNSUPPORTED` | hard | block every in-scope request | distinct "cannot verify" message |

`NETWORK_FAIL` **MUST NOT** render the security overlay. Conflating a CDN outage with
an attack trains users to ignore the one alert that matters, and turns a partial
outage into a self-inflicted incident.

### 8.3 Per-request outcomes

Evaluated only while the manifest state is `VALID` or `EXPIRED`:

| Condition | Outcome |
|---|---|
| cross-origin request | `PASSTHROUGH` — out of scope, CSP's job |
| same-origin, path outside `scope.include` or inside `scope.exclude` | `PASSTHROUGH` |
| same-origin, in scope, **not** in `assets` | `BLOCK_UNMANIFESTED` |
| in `assets`, hash already in Cache Storage | `SERVE_FROM_CACHE` |
| in `assets`, fetched, `sha256` + `size` + `content_type` all match | `SERVE_VERIFIED`, then cache under `sha256` |
| in `assets`, any of those mismatch | `BLOCK_TAMPER` |
| in `assets`, response was redirected | `BLOCK_TAMPER` |
| in `assets`, response is `206` | `PASSTHROUGH` (§7.3) |
| fetch threw | `NETWORK_FAIL` |

`BLOCK_UNMANIFESTED` is the allowlist behaviour and it is the default. A blocklist
would be defeated by the attacker simply choosing a filename that is not on it.

Cache Storage is keyed by `sha256`, not by URL. Eviction is normal browser behaviour
under storage pressure and **MUST** be handled as "re-fetch and re-verify", never as
tampering.

---

## 9. Rotation and revocation

### 9.1 Rotation statement

```json
{
  "spec": "veil-guard/rotation/1",
  "version": 1754500000,
  "from_trust_root_id": "…64 hex…",
  "to_trust_root": { "threshold": 2, "sigalgs": [ … ], "keys": [ … ] }
}
```

Signed with the `veil-guard/rotation/v1` prefix over the exact bytes of the statement
file, in a signature bundle of the same format as §5. A verifier accepts a rotation
only if:

1. `from_trust_root_id` equals the ID of the currently pinned root;
2. the bundle reaches the **old** root's threshold, under the old root's `sigalgs`,
   with the same present-but-invalid-is-fatal rule as §8.1 step 3;
3. `to_trust_root` satisfies every constraint in §4.4;
4. `version` is strictly greater than the version of the last accepted rotation, and
   greater than or equal to `pinned_version`.

Condition 4 is what stops an attacker from replaying an older rotation to walk the pin
back to a superseded root.

Rotation chains **MUST** be applied one link at a time and **MUST NOT** contain cycles;
a verifier **MUST** cap the number of links it will apply in one session at 8.

### 9.2 Revocation, and what it cannot do

A revocation statement marks `key_id`s as no longer trusted. It is signed with the
`veil-guard/revocation/v1` prefix and requires the trust root's threshold.

**A revocation cannot be delivered to Tier 1 by the compromised origin it protects.**
The origin serving the Service Worker is precisely the party a revocation would be
defending against, and it will simply not serve the statement. Revocation is therefore
a **Tier 0 and Tier 2 mechanism**: the CLI auditor and the browser extension fetch it
out-of-band. The Service Worker consumes a revocation only if it happens to receive
one, and its absence means nothing.

Implementations **MUST NOT** describe revocation as protecting Tier 1 clients.

---

## 10. Normative build pipeline

The CLI **MUST** execute these steps in this order:

```
1. Scan dist/, canonicalize paths (§7), reject symlinks and case collisions.
2. Compute SHA-256 and SHA-384 for every non-HTML asset.
3. Locate the byte offsets of asset-referencing tags in each HTML file.
4. Splice integrity="sha384-…" into those tags, in place, by byte offset.
5. Recompute SHA-256/SHA-384 for every HTML file — they changed in step 4.
6. Compute per-page inline-script SHA-256 for the CSP, from the post-splice bytes.
7. Build the manifest payload; serialize it once to bytes.
8. Sign those bytes with each available key, both algorithms; emit the bundle.
9. Write veil-guard-manifest.json and veil-guard-manifest.sig.
```

**Step 5 is not optional.** SRI attributes are written *into* the HTML, and the
manifest hashes the HTML. Signing before the splice produces a manifest whose HTML
hashes describe files that no longer exist on disk, and every client will correctly
report the build as tampered.

### 10.1 HTML must be spliced, not re-serialized

The generator **MUST** locate tags by byte offset and insert attributes into the
original byte buffer. It **MUST NOT** parse the document into a tree and serialize it
back out.

A parse/serialize round-trip rewrites attribute order, quoting style, character
references, void-element syntax, and whitespace. Two consequences, both fatal here:
the inline-script hashes computed for the CSP no longer describe the bytes that ship,
and framework hydration — Vue's in particular — compares server-rendered markup
against client-rendered markup and breaks on exactly these differences.

An HTML parser **MAY** be used, but only as a source of offsets.

---

## 11. Conformance vectors

`testdata/conformance_vectors.json` is the executable form of this document. Every
implementation **MUST** pass it. It is consumed by `cargo test` and by
`testdata/verify_vectors.mjs` under Node or Deno.

The file contains test-only key material and is generated once by
`testdata/gen_vectors.mjs`. **It must not be regenerated casually**: ECDSA P-256
signing is randomized, so a regeneration produces different — equally valid —
signatures, and the frozen values are what give the suite its cross-implementation
meaning. Ed25519 signing is deterministic per RFC 8032, so those vectors can be
reproduced exactly by any correct implementation, and the suite checks that they are.

Coverage required of any implementation claiming conformance:

- hex/binary encodings for both algorithms, including the `r‖s` versus DER and
  uncompressed-SEC1 versus SPKI distinctions of §2.1;
- `key_id` and `trust_root_id` derivation;
- signature verification under each domain prefix, and rejection of a signature
  presented under the wrong prefix;
- signature bundle parsing, including every rejection rule in §5;
- threshold logic: exactly at threshold, one below, present-but-invalid, absent,
  unknown `key_id`, unknown `alg_id`;
- rollback and rotation-replay rejection;
- NFC normalization of a path containing a composed character;
- percent-encoding rejections from §7.1.

---

## 12. Spec versioning

The string `veil-guard/1` covers everything in this document. Any change to a byte
layout, a domain prefix, a derivation, or the verification algorithm requires a new
spec string and new domain prefixes (`…/v2`). Verifiers **MUST** reject a manifest
whose `spec` they do not recognize rather than attempting a best-effort parse.

Additive, ignorable JSON fields do not require a version bump. Verifiers **MUST**
ignore unknown object members outside of `trust_root`, and **MUST** reject unknown
members inside `trust_root` — that object is hashed by a binary encoding, so a member
the verifier ignores would be a member the trust root ID does not cover.
