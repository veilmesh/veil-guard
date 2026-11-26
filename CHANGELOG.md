# Changelog

Versions of the `veil-guard` crate (CLI and embedded runtime) and of the
`@veilmesh/veil-guard-verify` npm package (the runtime's verifier and policy
modules). Earlier releases: see the `v0.1.0`, `v0.1.1` and `v0.2.0` tags.

## veil-guard 0.2.1 · @veilmesh/veil-guard-verify 0.4.0 — unreleased

### Fixed

- **A blocked navigation explains itself instead of showing a blank page**
  (issue #1003). A navigation blocked as tampered used to get an empty `526`,
  which Safari and Chrome show as a blank white page with no way out. It now
  gets a small self-contained page, still status `526`:
  - inline CSS only, no script, nothing it loads, and a CSP of
    `default-src 'none'`;
  - the failure in plain words, with the escaped path and the reason;
  - "Try again" and how to report it.

  A blocked subresource keeps the opaque empty `526`.
- **A deploy racing its manifest no longer locks the page.** Before blocking a
  navigation for its own HTML (hash or size mismatch), the worker reads the
  manifest once more, past every cache. It then judges the same bytes against
  the fresh manifest. A mismatch that survives is still blocked.
- **Navigations never stream.** A navigated page above the 512 KiB streaming
  threshold used to fail at the stream's flush, leaving a blank or half-drawn
  page. Navigations are now always judged whole, so they get the re-read and
  the explanation page too.

### Added

- `blockedResponseParts` and `blockedPage` in the policy module
  (`@veilmesh/veil-guard-verify/policy`).
- SPEC §8.4: what a blocked request is answered with.
- SPEC §8.5, for site operators: CDN features that rewrite HTML (RUM beacon
  injection, Rocket Loader, email obfuscation, auto-minify) break
  verification. It recommends `Cache-Control: no-transform` on HTML.
- CI: an audit of the live deployment from a second vantage point.
