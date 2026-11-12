# Security audit remediation plan

This document records the remediation plan for the security audit in
`/home/agent/security-audit-skill/kunato/run-1/` (target commit
`9d91a4563b70544bf9b0ced5431d5f62dbeba36f`). The audit confirmed 11 findings
(5 high, 6 medium, 0 critical) and left 8 source-grounded leads as
needs-validation. This file is the working record: each item lists the source
boundary, the intended fix, the regression test, and the acceptance criteria.

## Scope and policy

1. Add a regression test first: it must fail on the old behavior and pass after
   the fix.
2. Keep changes minimal and preserve the design invariants: fail closed, never
   panic while handling a request, bound every resource, and never weaken
   configuration reload safety.
3. Separate engine/proxy fixes (a binary release) from CI and signing fixes
   (effective on merge).
4. Correct `docs/attack-coverage.md` wherever a claim is stronger than the
   behavior the audit observed.
5. Do not treat the needs-validation leads as confirmed vulnerabilities. Apply
   cheap defensive fixes and leave the deployment-specific proof to the owner.

## Priority matrix

| ID | Severity | Area | Size | Delivery |
|---|---|---|---|---|
| F-03 | high | Quadratic JWT body scan | M | next release |
| F-02 | high | HTTP/3 request tasks retained after connection close | M | next release |
| F-04 | high | Root rules update follows a swapped symlink in `chown` | S/M | next release |
| F-05 | high | SSRF single-slash and backslash URL spellings | M | next release |
| F-07 | medium | JWT body tokens with encoded separators | S | next release |
| F-09 | medium | Redirect policy misses PHP-normalized names | S | next release |
| F-06 | medium | GraphQL-over-WebSocket envelopes bypass limits | M | next release |
| F-11 | medium | ZIP zero-entry EOCD hides local entries | S | next release |
| F-01 | high | Daily-CVE signing handoff can publish an ALLOW bypass | L | workflow |
| F-08 | medium | Daily-CVE job commits every workspace change | M | workflow |
| F-10 | medium | Release build jobs expose a write-scoped token | S | workflow |

## Phase 1: availability and privilege escalation

### F-03: linear JWT body scan

- Surface: `src/jwt.rs` (`check_text`).
- Change: split each decoded form once on the existing terminator set, count
  dots once per run, and only call `check_token` when the suffix has exactly two
  or four dots. Reject an oversized JWT-shaped suffix before scanning its tail.
  Do not use `spawn_blocking` or an async timeout as the fix; a synchronous loop
  cannot be interrupted, so the scan itself must be linear.
- Tests: a repeated-`eyJ` body with one dot returns no violation within a
  generous bound; a disallowed token embedded after a long `eyJ` run is still
  rejected; three- and five-part tokens still work; oversized tokens still fail
  closed.
- Acceptance: one 8 MiB request is bounded by a single pass over the body and
  the existing JWT decisions are unchanged.

### F-02: HTTP/3 request lifecycle

- Surface: `src/proxy/http3.rs` (`serve_h3`, `send_response`).
- Change: abort and reap request tasks when the QUIC connection ends (peer
  close, error, or idle watchdog). Allow a bounded drain for a local shutdown.
  Put an idle deadline on `body.frame()`; on expiry stop the stream with
  `H3_REQUEST_CANCELLED`. Keep `ConnectionGuard` owned by the connection task
  so it drops when the connection ends.
- Tests: a mock upstream sends response headers and then stalls; the client
  reads the headers and closes the QUIC connection; a second client is admitted
  under `max_connections: 1` within a short bound.
- Acceptance: a stalled upstream body cannot retain the process-wide or
  per-source connection budget after the client is gone.

### F-04: descriptor-based ownership

- Surface: `src/rules_update.rs` (`write_atomic`, `target_attributes`,
  `set_owner`).
- Change: keep the created file open and use `fchown` on its descriptor before
  the rename. Read replacement attributes with `symlink_metadata` and treat a
  symlink as an unknown file. After the rename, verify the installed path is a
  regular file with the same device and inode as the open descriptor; otherwise
  remove it and fail.
- Tests: mode preservation still works; a symlink at the rules path is replaced
  by a regular file; a swapped temporary name cannot change the target's owner;
  `target_attributes` returns safe defaults for a symlink.
- Acceptance: no path-based `chown` remains in the atomic writer and a root
  update cannot transfer ownership of an attacker-chosen target.

## Phase 2: inspection bypasses

### F-05 and F-09: URL and parameter normalization

- Surface: `src/hardening.rs`.
- Change: share one URL normalizer between the SSRF and redirect paths. Remove
  tabs, CR, and LF, map `\` to `/`, and accept a special scheme (`http`,
  `https`, `ws`, `wss`, `ftp`, `file`) followed by zero, one, or two slashes.
  Restrict the no-slash form to special schemes to avoid treating every
  `word:value` text as a URL. Normalize redirect parameter names with
  `form_value` and `php_parameter_name` before comparison.
- Tests: `http:/internal`, `http:\internal`, `http:internal`, and the header
  spelling are rejected; a benign `note:metadata.internal` is not. Redirect
  names with dots, spaces, plus signs, and encoded dots are rejected in query
  and form bodies; the exact name and an unrelated parameter still work.
- Acceptance: alternate spellings cannot reach a configured internal host or
  bypass the redirect allowlist.

### F-07: JWT body decoding

- Surface: `src/jwt.rs`.
- Change: remove the literal-dot body prefilter and inspect the raw body plus
  `decoding::decoded_body_forms`. That applies form percent decoding and JSON
  string unescaping before token extraction.
- Tests: `%2E` and `\u002E` tokens are rejected, including a body with an
  unrelated literal dot; the allowed algorithm controls still pass.
- Acceptance: every representation the origin can decode is inspected, with no
  CPU regression once F-03 is in place.

### F-06: GraphQL-over-WebSocket envelopes

- Surface: `src/graphql.rs` (`QueryDocuments`), `src/proxy/websocket.rs`.
- Change: collect `payload.query` for `start` and `subscribe` messages, keep
  non-operation messages tolerant, and return `Violation::Uninspectable` when
  an operation-bearing envelope has no extractable document. The WebSocket pump
  closes the tunnel with `1008` on any violation.
- Tests: introspection and deep queries in both envelope dialects are rejected;
  an `operation` without a document is uninspectable; `connection_init` passes;
  a `/graphql` tunnel receives a close frame before the upstream sees the frame.
- Acceptance: the GraphQL limits apply to tunneled operations unless the
  upstream does not support the protocol at all.

### F-11: ZIP zero-entry EOCD

- Surface: `src/upload.rs` (`zip_expansion`).
- Change: when the EOCD declares zero entries, scan the archive body for a local
  file header and reject the archive as malformed if one exists. A genuinely
  empty archive still passes.
- Tests: a deflate entry hidden behind a zero-count EOCD is rejected with 400;
  an empty archive passes; the existing hybrid, listed-entry, trailing-byte, and
  ZIP64 tests keep passing.
- Acceptance: an archive detected by a valid EOCD cannot hide local entries
  from the expansion budget.

## Phase 3: CI and signing

### F-10: release workflow token scope

- Change: workflow-level `contents: read`; grant `contents: write` only to the
  release job; set `persist-credentials: false` on build checkouts; pin actions
  to full commit SHAs.
- Tests: actionlint and a fork tag run; a build step cannot push and the
  checkout credential is absent.
- Acceptance: only the publishing job has write authority.

### F-08: scoped daily-CVE commit

- Change: split the workflow into a read-only verification job and a signing
  job that runs no build code. Stage only the rule artifact and corpus paths,
  fail on any other tracked or untracked change, and reject deletions in
  `blocked.txt` and `allowed.txt`.
- Tests: on a fork, a build-written file outside the allowlist fails the commit;
  a legitimate run commits only the expected files.
- Acceptance: build code cannot inherit the rule artifact's push authority.

### F-01: signing oracle

- Change: run the black-box gate against the exact `dist/rules.yaml` that is
  signed (`rules_file` layout), add a deterministic ALLOW policy gate before
  minisign, and enforce an append-only corpus. The policy gate permits only
  reviewed ALLOW actions, requires `trusted-sources` to stay disabled, and
  rejects every rule-level ALLOW. Sign only after the gates pass.
- Tests: an enabled ALLOW fixture fails the gate; a deleted corpus line fails;
  the shipped set passes; the black-box test uses the exact published file.
- Acceptance: an injected ALLOW cannot be signed and the tested bytes are the
  signed bytes (apart from a documented, narrow test-only neutralization).

## Phase 4: needs-validation leads

These are not confirmed vulnerabilities. Apply the defensive fix and leave the
deployment-specific proof to the owner.

| ID | Action |
|---|---|
| N-01 | Reject `CONNECT` with a body at head validation. Reverse proxying does not implement tunnels. |
| N-02 | Remove a client `X-Forwarded-Host` like the other legacy identity headers and insert only a canonical value. |
| N-03 | Reject data-plane `X-Forwarded-*` markers on the admin listener, require a Host, warn when the upstream overlaps `admin.listen`, and render the admin block in `kunato init`. |
| N-04 | Reduce the speculative decoy scratch reservation and add the deterministic reservation test. |
| N-05 | Disable QUIC active migration by default, or re-resolve the client identity per request. Document the trade-off. |
| N-06 | Normalize PHP upload-progress field names with the same helper as the duplicate and redirect checks. |
| N-07 | Use `--locked` in CI and release checks and gate the post-bump `Cargo.lock` diff. |
| N-08 | Create starter rules with `create_new`/no-follow semantics and replace the shell redirect with an atomic write from a root-owned directory. |

## Phase 5: hardening backlog

These items are defense-in-depth rather than confirmed exploitable findings.
They are implemented in the same change because they close gaps the audit
recorded under `hunter_hardening`.

- Deny yanked releases, add the `aarch64-unknown-linux-musl` target, and
  allowlist every reviewed build-script crate in `deny.toml`.
- Add a total HTTP/3 response deadline in addition to the idle deadline, so an
  origin that drips frames just inside the idle interval cannot hold a request
  task and its connection slot indefinitely.
- Strip terminal control and escape sequences from admin-client output before
  printing it, and cap a single journal line before parsing it.
- Key the inspection budget with `protection::tracking_key` so the per-source
  dimension matches limits, bans, and allowlists, including IPv6 aggregation.
- Require a start anchor on `content_routes[].path` so an unanchored pattern
  cannot exempt a different subtree.
- Apply the opt-in JWT body policy to WebSocket client frames.
- Pin workflow actions to commit SHAs, use `--locked` in CI and release cargo
  commands, and scope `contents: write` to the publishing job. These are
  covered by F-10 and N-07 and repeated here because they are part of the same
  hardening pass.

## Verification gate

Run, in order:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
./scripts/check-deny.sh
cargo test
cargo fmt --manifest-path blackbox/Cargo.toml
cargo clippy --manifest-path blackbox/Cargo.toml --all-targets -- -D warnings
./scripts/blackbox-test.sh
./scripts/check-rules-compat.sh
```

Then re-run the bounded reproductions from the audit: the 8 MiB JWT body, the
stalled HTTP/3 origin, the symlink swap, the alternate SSRF spellings, the
WebSocket GraphQL envelope, the encoded JWT body, the PHP-normalized redirect
name, and the zero-entry EOCD ZIP. CI changes are validated on a fork with a
dry run; do not use the production signing keys.

Documentation to update with the code: `docs/development.md` (SSRF, redirects,
JWT, GraphQL, upload expansion), `docs/attack-coverage.md` (the affected rows),
`docs/rule-updates.md`, and `docs/release-signing.md`.

## Implementation status

The fixes below are implemented in this tree. The verification commands were
run locally with Rust 1.99.1.

| ID | Status | Fix and regression evidence |
|---|---|---|
| F-01 | fixed | `scripts/blackbox-test.sh` now runs the exact `dist/rules.yaml` as `rules_file`; `scripts/check-rules-policy.py` and `.github/rules-policy-allowlist` reject an enabled ALLOW category or rule-level ALLOW before signing. The scanner fails closed on every non-canonical spelling the config parser accepts (quoted keys, explicit `?` keys, indentless sequences, and unusual indentation), so an ALLOW cannot hide from the gate. The signing job checks that the corpus is append-only; signing moved after all gates; the opencode installer is pinned to a version. Negative fixtures are covered by `scripts/test_check_rules_policy.py`. |
| F-02 | fixed | `serve_h3` aborts request tasks when the QUIC connection ends; `send_response` bounds upstream body reads with `connection_idle`. `http3_client_close_releases_the_connection_budget` fails with `CONNECTION_REFUSED` on the old code and passes now. |
| F-03 | fixed | `check_text` segments each run once and only examines two- or four-dot suffixes, bounding oversized JWT shapes. Unit tests: `repeated_eyj_body_is_scanned_linearly`, `a_token_embedded_after_a_long_marker_run_is_still_rejected`, `an_oversized_jwt_shaped_run_fails_closed`. |
| F-04 | fixed | `write_atomic` uses `fchown` on the open descriptor, `symlink_metadata` for the replacement target, and a post-rename device/inode check. Unit tests cover mode preservation, a symlink target, a pre-existing symlink, and a planted-link ownership change. |
| F-05 | fixed | `internal_host_in` normalizes tabs, CR/LF, backslashes, and zero/one/two separators for WHATWG special schemes; no-slash forms are limited to those schemes. Tests cover query, header, userinfo, and negative `note:metadata.internal`. |
| F-06 | fixed | `QueryDocuments` reads `payload.query` for `start`/`subscribe`, rejects an operation envelope without a document, and stays tolerant of `connection_init`/`ping`/`complete`. The WebSocket pump closes with `1008`; `graphql_over_websocket_envelopes_are_rejected_before_forwarding` fails on the old code and passes now. |
| F-07 | fixed | Body inspection now covers the content-type decoded forms in addition to the raw body. Tests cover `%2E`, `\u002E`, a decoy literal dot, and an allowed RS256 control. |
| F-08 | fixed | `daily-cve.yml` separates the read-only `verify` job from the signing job; the sign job runs no cargo, stages only the rule artifact and corpus paths, and fails on unexpected changes. |
| F-09 | fixed | `redirect_in_pairs` applies `form_value` and `php_parameter_name` to both sides. Tests cover query, form, plus, and encoded-dot spellings and the exact-name control. |
| F-10 | fixed | `release.yml` grants `contents: write` only to the release job, uses `persist-credentials: false` on every checkout, and pins actions to commit SHAs. Other workflows use the same pins. |
| F-11 | fixed | A zero-entry EOCD with a local file header is `ArchiveMalformed`; a genuinely empty archive still passes. Tests cover both and the existing hybrid/listed-entry cases. |
| N-01 | fixed | `CONNECT` is rejected with `405` at head validation before any body read; `connect_requests_are_rejected_before_the_body_is_forwarded` covers it. |
| N-02 | fixed | `x-forwarded-host` is in `LEGACY_IDENTITY_HEADERS`; a missing Host removes the client value instead of forwarding it. `a_client_x_forwarded_host_without_a_host_is_stripped` covers it. |
| N-03 | fixed | The admin listener rejects data-plane `X-Forwarded-*` markers and a missing Host; startup warns when the upstream is the admin socket; `kunato init` renders the admin block. Unit tests cover the markers and Host policy. |
| N-04 | fixed | The decoy scratch reservation is now `SCAN_BYTES` instead of `64 KiB + 6 * path`; `decoy_scratch_reservation_is_bounded_and_reclaimable` asserts the reservation and reclaim path. |
| N-05 | fixed | QUIC active migration is disabled. Deployment validation of a migrated client remains an owner check. |
| N-06 | fixed | `form.rs` compares PHP-normalized upload-progress names without changing case; `php_normalizes_upload_progress_field_names` covers dotted, spaced, and differently-cased fields. |
| N-07 | fixed | CI, clippy, and tests use `--locked`; `release.sh` fails when the version bump changes dependency resolution in `Cargo.lock`. |
| N-08 | fixed | `write_starter_rules` uses `create_new` and rejects non-regular paths; the installer writes the empty fallback from the root-owned configuration directory and renames it. Main-crate tests cover the symlink refusal and regular-file creation. |
| P5-1 | fixed | `deny.toml` denies yanked releases, adds the `aarch64-unknown-linux-musl` target, and allowlists every reviewed build-script crate. `./scripts/check-deny.sh` runs all three targets. |
| P5-2 | fixed | `timeouts.response_body` (default `5m`) bounds the whole HTTP/3 response stream in addition to the idle deadline; `http3_total_response_deadline_ends_a_dripping_stream` covers a stalled origin. |
| P5-3 | fixed | The admin client strips C0/C1 controls and CSI/OSC escape sequences before printing; `admin_output_drops_terminal_control_sequences` covers it. |
| P5-4 | fixed | `kunato log` caps one journal line at 64 KiB before parsing and marks an oversized line; `journal_lines_are_capped_before_parsing` covers it. |
| P5-5 | fixed | The inspection budget now keys per-source reservations with `protection::tracking_key`, so IPv6 aggregation is consistent with limits, bans, and allowlists; `inspection_budget_uses_the_protection_tracking_key` covers a shared /64. |
| P5-6 | fixed | `content_routes[].path` must be anchored at the start; `rejects_invalid_content_routes` covers an unanchored pattern. |
| P5-7 | fixed | The opt-in JWT body policy also checks WebSocket client frames; `websocket_frames_are_checked_by_the_jwt_policy` covers an HS256 frame. |

Local verification:

```text
cargo fmt                                              pass
cargo clippy --all-targets --locked -- -D warnings      pass
./scripts/check-deny.sh                                pass
cargo test --locked                                    1066 passed (0 failed)
cargo fmt --manifest-path blackbox/Cargo.toml --check   pass
cargo clippy --manifest-path blackbox/Cargo.toml --all-targets --locked -- -D warnings
                                                        pass
./scripts/blackbox-test.sh                             PASS (704 allowed, 2242 blocked)
./scripts/check-rules-compat.sh                        pass (v0.17.1)
python3 scripts/test_check_rules_policy.py             pass
actionlint .github/workflows/*.yml                     pass
daily-cve guard simulation                             pass
  (corpus deletion rejected; build-written src/trust.rs rejected)
```

The workflow changes are source-reviewed but not executed on GitHub Actions:
the `verify`/`sign-and-push` split, the exact-artifact black-box run, the
policy check, and the scoped commit should be exercised once on a fork with
`workflow_dispatch` and `dry_run: true` before the next scheduled run. Owner
validation in `NEEDS-VALIDATION.md` is still required for the deployment
specifics of N-01 (non-consuming origin), N-03 (effective upstream overlap),
N-05 (a migrated client), N-06 (a real PHP session), and N-08 (host-root
installer behavior); the source-side defenses are in place.
