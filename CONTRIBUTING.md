# Contributing

## The one rule that is not negotiable

`SPEC.md` is normative. Two implementations of it live in this repository — the Rust
CLI and the JavaScript verifier under `runtime/` — and they must reach the same verdict
on every input. Where the document and an implementation disagree, the document wins
and the implementation is the bug.

A change to a byte layout, a domain prefix, a derivation or the verification algorithm
is a change to `SPEC.md` first, then to both implementations, then to
`testdata/conformance_vectors.json`. Not in another order.

## Getting set up

```bash
cargo build
cargo test
```

The auditor and everything that reaches the network sit behind feature flags, so the
default build has no network code in it at all. To exercise all of it:

```bash
cargo test --all-targets --features audit,kms,vault,rekor,relay-client,relay-server,telemetry-server
```

The JavaScript side is plain Node, no dependencies:

```bash
node testdata/verify_vectors.mjs      # conformance vectors, both algorithms
node testdata/verify_policy.mjs       # Tier 1 decision logic
node testdata/verify_wasm_hasher.mjs  # the embedded streaming hasher
```

## Before you open a merge request

```bash
cargo fmt --all
cargo clippy --all-targets --features audit,kms,vault,rekor,relay-client,relay-server,telemetry-server -- -D warnings
```

CI runs exactly these, plus an end-to-end pass that signs a build, cross-verifies it
with the JavaScript verifier, evaluates the generated Service Worker, and then flips a
byte to confirm the whole thing still refuses tampered output.

## About the conformance vectors

`testdata/conformance_vectors.json` is generated once and then frozen. Ed25519 signing
is deterministic so those regenerate identically, but **ECDSA P-256 signing is
randomized** — regenerating mints different, equally valid signatures and destroys the
cross-implementation meaning of the file. `gen_vectors.mjs` reuses the existing P-256
keys and the `_frozen_p256` block for exactly this reason.

Adding a vector is fine. Deleting the file to "start clean" is not.

## Tests we actually want

The bugs this project has shipped and then found all had the same shape: code whose
failure is silent. A wrong digest rather than an exception. A verdict computed and then
discarded. A hook that fires at the wrong moment and signs an incomplete tree. A test
that reimplements the behaviour it is meant to check and therefore passes with the
feature removed.

So: prefer a test that runs the real binary or the real bundle over one that calls a
function you have just written, and prefer an assertion that would fail if the feature
were deleted. If you are adding a network integration, add the negative paths too —
wrong length, wrong hash, endpoint down, endpoint lying.

## Commit messages

Say what was wrong and why the change is the fix. "Fix bug" tells the next person
nothing; the reason a check exists is the part that is expensive to recover later.

## Licence

By contributing you agree your work is licensed under MIT OR Apache-2.0, matching the
project.
