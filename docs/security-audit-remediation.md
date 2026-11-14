# Security audit remediation plan

This document holds the remediation plan for every security audit of this
repository. Each audit is one top-level section with its own scope, priority
matrix, phases, verification gate and implementation status.

- **First audit (2026-10-23, commit `9d91a45`)** — 11 findings, 8 leads. Its
  section follows this introduction and is complete.
- **Second audit (2026-11-14, commit `9cc7109`)** — 16 findings, 3 leads, and one
  workflow-ordering defect. Its section is appended after the first audit and
  starts at "Second audit: 2026-11-14".

This document is the working record: each item lists the source
boundary, the intended fix, the regression test, and the acceptance criteria.

## First audit (2026-10-23): scope and policy

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

---

# Second audit: 2026-11-14

This section records the remediation plan for the security audit in
`/home/hiroe/security-audit-skill/kunato/run-1/` (target commit
`9cc7109655d5d41a5fadf7c9407738135b31f9c7`). The audit confirmed 16 findings
(3 high, 10 medium, 3 low), left 3 source-grounded leads as needs-validation,
and recorded one workflow-ordering defect discovered while validating the
findings. Full evidence, traces and patch sketches live in that run's
`REPORT.md`, `FINDINGS-DETAIL.md` and `findings.json`.

## Second-audit scope and policy

1. Add the regression test first: it must fail on the old behavior and pass
   after the fix. Every item below names the test that proves it.
2. Keep changes minimal and preserve the design invariants: fail closed, never
   panic while handling a request, bound every resource, and never weaken
   configuration reload safety.
3. **Fix the rule-pipeline gates (S-12 to S-16) before repairing the
   verify/signing ordering (W-01).** The ordering regression is currently the
   only control that stops a weakened managed rule set from being signed; it is
   an accident, not a defense, so it must be repaired last and deliberately.
4. Separate engine fixes (a binary release) from CI, workflow and installer
   fixes (effective on merge).
5. Do not treat the three needs-validation leads (L-01 to L-03) as confirmed
   vulnerabilities. Apply the cheap defensive fix and leave the
   deployment-specific proof to the owner.
6. Correct `docs/attack-coverage.md` wherever a fix changes a verdict (SAML
   structural checks, request-target path inspection, HTTP/3 head and
   connection bounds, GraphQL document sources, JWT body policy, WebSocket
   hot-reload behavior) and `docs/release-signing.md` for W-01. The coverage
   tracker must not claim more than the code enforces.

## Second-audit priority matrix

| ID | Severity | Area | Size | Delivery |
|---|---|---|---|---|
| S-01 | high | Process-wide inspection budget exhaustion (503 to every client) | M | next release |
| S-02 | high | HTTP/3 idle close pins connection slots | S | next release |
| S-03 | high | HTTP/3 HEADERS buffered before the field-section limit | M | next release (in-tree wrapper; remove after an h3 upgrade) |
| S-04 | medium | Authority-form request target skips path rules (HTTP/1.1 and HTTP/3) | S | next release |
| S-05 | medium | GraphQL envelope hides the executed document from complexity checks | S | next release |
| S-06 | medium | Concatenated zstd frames after the first are forwarded uninspected | S | next release |
| S-07 | medium | SAML guard skipped by an escaped field name | S | next release |
| S-08 | medium | SAML assertion-placement check accepts a nested `Response` | S | next release |
| S-09 | low | SAML message beyond the inspection prefix is forwarded uninspected | S | next release |
| S-10 | low | Opt-in JWT body policy does not force body decoding | S | next release |
| S-11 | low | WebSocket tunnels keep a stale content-route exemption after reload | S | next release |
| S-12 | medium | ALLOW policy gate accepts non-canonical spellings | M | workflow |
| S-13 | medium | Oversized rules validator erases the rollback floor | S | next release |
| S-14 | medium | Black-box gate passes when the driver fails | S | workflow |
| S-15 | medium | Black-box driver injects `Host`/`Content-Length` | S | workflow |
| S-16 | medium | Append-only corpus guard treats a binary diff as zero deletions | S | workflow |
| W-01 | high (process) | Verify job runs the committed-signature test against an unsigned candidate | S | workflow |
| L-01 | lead | SSRF host canonicalization (IPv4/IDNA aliases) | S | next release + owner check |
| L-02 | lead | Redirect/duplicate-parameter checks inspect one decode pass | S | next release + owner check |
| L-03 | lead | `kunato init` follows a symlink in a privileged write | S | next release + owner check |

## Phase A: availability (high)

### S-01: process-wide inspection budget exhaustion

- Surface: `src/proxy/server.rs` (`INSPECTION_BUDGET_BYTES`,
  `MIN_INSPECTION_RESERVATION`, `reserve_request_inspection`,
  `grow_request_inspection_raw`).
- Change: stop reserving a fixed 64 KiB baseline before a body byte exists.
  Reserve zero at admission and reserve exactly the bytes actually buffered as
  frames arrive. Do not replace the floor with a smaller one: a one-byte body
  must not reserve 64 KiB, and the read-path growth must be the only consumer of
  the shared budget. A request that buffers nothing must not deny admission to
  anyone.
- Tests: `audit_many_sources_do_not_exhaust_the_process_inspection_budget`
  (N sources with stalled bodies cannot make a clean client's reservation
  fail), `inspection_guard_grows_and_releases_its_reservation` still passes, and
  a request held to the `body_read` deadline releases its reservation.
- Acceptance: with default limits, many source identities that each hold the
  maximum number of stalled requests cannot push the shared budget to
  exhaustion, and a clean bodyless GET keeps being admitted.

### S-02: HTTP/3 idle close pins connection slots

- Surface: `src/proxy/http3.rs` (`serve_h3` idle and shutdown close arms).
- Change: bound both `connection.shutdown(0)` awaits with a short deadline
  derived from `connection_idle` (for example `idle.min(Duration::from_secs(1))`),
  and always fall through to `requests.abort_all()` and the unconditional guard
  drop.
- Tests: `http3_idle_close_can_hang_on_control_stream_credit` (advertise a
  SETTINGS-sized uni-stream window, never read the server control stream, keep
  the QUIC connection alive; a second source is admitted after
  `header_read`/`connection_idle`), plus a control with a large window.
- Acceptance: a peer cannot hold a `ConnectionGuard` past the documented idle
  bound, and the close still completes promptly when the peer grants credit.

### S-03: HTTP/3 HEADERS buffering before the field-section limit

- Surface: `src/proxy/http3.rs` (h3 builder), dependency `h3 0.0.8`.
- Change: reject a HEADERS frame whose declared length exceeds
  `limits.max_header_bytes` before its payload is accumulated. Preferred: an
  upstream h3 release (or a vendored patch) that enforces
  `max_field_section_size` from the declared frame length, and the same guard
  for trailer HEADERS. Fallback: a stream adapter that fails a request stream
  once more than `max_header_bytes` bytes are read before the head resolves.
- Tests: `http3_buffers_oversized_headers_frame_before_the_field_section_limit`
  (declares 256 MiB and delivers 24 MiB with the default 10 s `header_read`;
  server RSS must not grow by the delivered bytes and the stream must be
  rejected), plus a conforming 32 KiB frame that still works.
- Acceptance: an incomplete, over-limit HEADERS frame cannot retain more than
  `max_header_bytes` per stream, and the documented 431 path still applies to
  complete oversized heads.

## Phase B: inspection bypasses

### S-04: authority-form request target

- Surface: `src/proxy/server.rs` (`request_head_error`).
- Change: reject a request target that does not carry an absolute path before
  policy evaluation: require `parts.uri.path_and_query()` and a `/`-prefixed
  path, except `OPTIONS *`. The same check covers the HTTP/3 header block
  without `:path`/`:scheme`, which produces the same empty path.
- Tests: `authority_form_request_targets_are_rejected` (unit, both
  authority-form spellings), `authority_form_request_target_is_rejected_before_forwarding`
  (HTTP/1.1 `GET host:port` -> 400), `http3_header_block_without_path_is_rejected_before_forwarding`
  (raw QPACK block without `:path`/`:scheme` -> not forwarded), and controls that
  origin-form, absolute-form and `OPTIONS *` keep working.
- Acceptance: every forwarded request is inspected on the path the upstream
  routes on, on HTTP/1.1, HTTP/2 and HTTP/3.

### S-05: GraphQL envelope hides the executed document

- Surface: `src/graphql.rs` (`collect_json_body_queries`,
  `collect_json_text_queries`).
- Change: inspect the union of every document the transport may execute
  (top-level `query`, `payload.query`, batch entries, multipart `operations`)
  instead of selecting a branch from the attacker-supplied `type`. Keep
  `Uninspectable` only for an operation envelope with no document at all.
- Tests: `graphql_envelope_cannot_hide_a_top_level_query` (deep document behind
  `{"type":"start","payload":{"query":"{a}"}}` -> 400), the unit tests above,
  plus the existing plain, batch, form and multipart cases.
- Acceptance: the depth/field/introspection limits apply to every document the
  upstream may execute, and the WebSocket envelope behavior is unchanged.

### S-06: concatenated zstd frames

- Surface: `src/decoding.rs` (`decode_body_for_inspection`, zstd branch;
  `read_bounded`).
- Change: decode every concatenated frame the way `MultiGzDecoder` handles gzip
  members: reinitialize the decoder at each frame boundary with the remaining
  input, return `Complete` only when the input is exhausted, `Truncated` when
  the output limit is reached, and `Malformed` for trailing non-frame bytes.
- Tests: `zstd_concatenated_frames_are_inspected` (empty first frame + payload
  frame: decoded output must contain the second frame), a single-frame control,
  an over-limit two-frame body -> 413, and a garbage-suffix body -> 400.
- Acceptance: a request body is never forwarded with an encoded body that
  could not be fully inspected, for gzip and zstd alike.

### S-07: SAML guard skipped by an escaped field name

- Surface: `src/saml.rs` (`messages`, `has_saml_marker`, `form_messages`,
  `json_messages`).
- Change: remove the raw-byte `has_saml_marker` early return (or replace it
  with a prefilter that is a superset of the extractors' key decoding) and
  attempt form/JSON extraction for every body of a SAML-capable media type; the
  extractors already return `None` when no SAML field is present.
- Tests: `saml_escaped_field_name_is_inspected` (`SAM%4CResponse`,
  `S%41MLResponse`, `SAM%4cResponse`, `S\u0041MLResponse`,
  `SAM\u004cResponse` -> 403 with the same payload that a literal field name
  rejects), the `note=SAML` re-enable control, and a double-encoded negative.
- Acceptance: every form/JSON representation the origin can decode to a
  `SAMLResponse`/`SAMLRequest` reaches the structural checks.

### S-08: SAML assertion placement

- Surface: `src/saml.rs` (`Analyzer::element`).
- Change: anchor the placement check to the message root: report
  `AssertionOutsideResponse` unless the assertion's parent is the root element
  and the root local name is `Response`; reject a root-level assertion as well.
- Tests: `saml_assertion_outside_response_is_rejected` (nested
  `<samlp:Extensions><samlp:Response>` wrapper and a root-level signed
  assertion -> 403), the Extensions-direct control, and a legitimate direct
  child that still passes.
- Acceptance: strict mode rejects any plaintext assertion that is not a direct
  child of the message `Response`.

### S-09: SAML truncation fail-open

- Surface: `src/proxy/server.rs` (`inspect_body`, strict over-limit gate) and
  `src/saml.rs` (`inspect`).
- Change: treat SAML as a body-completeness consumer: include `saml_body` in the
  strict over-limit rejection and pass `body_truncated` into `saml::inspect`,
  returning a blocking `TooLarge`/`Incomplete` finding for a SAML-capable body
  that could not be read in full (mirror `graphql::Violation::Incomplete`).
  Document the fail-closed trade-off for over-limit JSON bodies that carry no
  SAML field, and apply the same rejection under `body_inspection: stream`.
- Tests: `saml_truncated_json_body_is_rejected` (DTD payload after the
  `max_body_bytes` cut -> 413), the under-limit control -> 403, the form carrier
  -> 413, and a deployment with one `in: [body]` rule as the existing control.
- Acceptance: a SAML message that cannot be read in full is never forwarded.

### S-10: JWT body policy does not force decoding

- Surface: `src/proxy/server.rs` (`inspect_body`).
- Change: include an enabled `limits.jwt` in the body-inspection requirement so
  `decode_body` decodes supported `Content-Encoding` values and the strict
  over-limit rejection applies; reject unsupported encodings instead of
  forwarding.
- Tests: `jwt_body_policy_decodes_and_bounds_the_body` (plain HS256 -> 403
  control; gzip JSON with `limits.saml.mode: off` -> 403; over-limit body with
  `max_body_bytes: 64` -> 413; text/plain gzip under defaults -> 403).
- Acceptance: with `limits.jwt` enabled, a body-borne token either reaches the
  scan fully decoded or the request fails closed.

### S-11: WebSocket content-route exemption after reload

- Surface: `src/proxy/websocket.rs` (`forward_handshake`,
  `pump_client_to_upstream`).
- Change: recompute the content-route decision from the live configuration for
  every message; remove the handshake-captured `body_rules_exempt` boolean and
  its threading.
- Tests: `websocket_content_route_removal_applies_to_open_tunnels` (open a
  tunnel on a content route, reload without it, the next matching frame closes
  with 1008; a fresh tunnel closes too).
- Acceptance: established tunnels follow a hot reload exactly as fresh requests
  do, as documented.

## Phase C: rule-pipeline and signing integrity

### S-12: ALLOW policy gate spellings

- Surface: `scripts/check-rules-policy.py` and its self-test.
- Change: replace the fixed-column scanner with a positive structural allowlist:
  accept only `  - name: NAME` category entries, `      - name: NAME` rule
  entries, and the canonical key columns; reject every other sequence entry,
  key or indentation. This is the shape the generator emits, so a future schema
  addition must extend the allowlist (fail-closed direction). Add regression
  cases for all five demonstrated spellings (tab after the dash, uniformly
  deeper block, bare dash, nested name scalar, `enabled:`-first entry).
- Tests: `scripts/test_check_rules_policy.py` cases for each spelling plus the
  canonical enabled-ALLOW control; the pristine `rules.example.yaml` and
  `dist/rules.yaml` must still pass.
- Acceptance: no YAML spelling the in-tree parser accepts can place an enabled
  ALLOW category outside the gate's view.

### S-13: rollback floor erased by response metadata

- Surface: `src/rules_update.rs` (`MAX_STATE_BYTES`, `UpdateState::read`,
  `fetch`, `update_candidate`).
- Change: bound `ETag`/`Last-Modified` at capture (ignore values above a few
  hundred bytes), persist `signature_timestamp` in a separate fixed-format
  record that validators cannot resize, and fail the update closed when an
  existing state/floor record is unreadable or oversized while a trusted key is
  configured.
- Tests: `oversized_etag_does_not_erase_the_rollback_floor` (a 20 KiB ETag
  leaves the floor readable and the older candidate still refused), a
  first-install control, and an unreadable-state fail-closed case.
- Acceptance: a rules response cannot make the install accept a candidate older
  than the installed signed timestamp.

### S-14: black-box gate passes when the driver fails

- Surface: `scripts/blackbox-test.sh`, `scripts/blackbox-report.py`.
- Change: keep the driver's exit status and fail on a non-zero value; require
  one parsed result per corpus line (or reconcile the driver's per-phase totals
  with the corpus) before the report may print PASS.
- Tests: a shell/report regression test with (a) a zero-byte log, (b) a
  malformed corpus line that aborts the driver, (c) a partial log, and (d) a
  clean run.
- Acceptance: the gate fails when the corpus did not execute.

### S-15: black-box driver injects `Host`/`Content-Length`

- Surface: `blackbox/src/main.rs` (`send_http1`, `parse_request`).
- Change: emit the driver `Host` only when the corpus supplies none (or add an
  explicit authority attribute), and suppress the automatic framing header when
  the corpus declares `Content-Length`/`Transfer-Encoding`. Add an optional
  expected-status/expected-rule field so a generic parser 400 cannot stand in
  for a rule block.
- Tests: a unit test over the built request head for the 17 Host-carrying
  corpus lines (exactly one Host), the `blocked.txt:960` framing line (one
  `Content-Length`), and a gate run with the `malformed-host-header` rule
  removed that must fail.
- Acceptance: a blocked corpus line exercises the rule it names; removing that
  rule fails the gate.

### S-16: append-only corpus guard and binary diffs

- Surface: `.github/workflows/daily-cve.yml` (append-only step).
- Change: compare bytes against the committed blob (`git show HEAD:<path>` and
  require the current file to start with those bytes) instead of summing
  `git diff --numstat` deletions, so a NUL byte cannot zero the count.
- Tests: a workflow regression fixture with (a) a NUL-containing deletion, (b) a
  plain deletion, (c) a legitimate append, (d) no change.
- Acceptance: no corpus edit other than a true prefix append is accepted,
  regardless of the file's byte content.

### W-01: verify/signing ordering (fix last)

- Surface: `.github/workflows/daily-cve.yml` (verify and sign-and-push jobs),
  `src/trust.rs` (`the_committed_rules_signature_is_valid`),
  `docs/release-signing.md`.
- Change: the verify job regenerates `dist/rules.yaml`, so it necessarily holds
  an unsigned candidate. Do not run the committed-pair test against that
  candidate in verify; run it on the post-signing artifact (or on `main` after
  the signing job) and correct `docs/release-signing.md:121`. Keep the
  sign-and-push job's own signature verification with the embedded rules key.
- Tests: a workflow dry run on a fork where a categories change reaches the
  black-box step and signs, and a control where an invalid signature is
  rejected.
- Acceptance: a legitimate rule-set change can be published, and a weakened one
  cannot pass the repaired gates. **Sequence:** land S-12 to S-16 first.

## Phase D: needs-validation leads

These are not confirmed vulnerabilities. Apply the defensive fix and leave the
deployment-specific proof to the owner.

| ID | Action |
|---|---|
| L-01 | Normalize the SSRF host comparison through a shared canonicalizer (numeric IPv4 forms, UTS46/IDNA dots) so an alias cannot differ from the configured internal host. Owner: confirm the upstream fetcher canonicalizes the same forms. |
| L-02 | Make `redirect_target` and `duplicate_parameter` consume every `query_forms` entry, not only the first raw form, matching `internal_host`. Owner: confirm whether the route decodes parameters a second time. |
| L-03 | Replace `run_init`'s `exists()` + `std::fs::write` with the no-follow/atomic pattern already used by `write_starter_rules` and `rules_update::write_atomic` (create_new temp 0640, fsync, rename over the path). Owner: confirm no privileged init runs in a lower-trust-writable directory. |

## Phase E: hardening backlog

Cheap, non-blocking improvements recorded by the hunters; none is a finding.

- Admin listener: reject a non-loopback `Origin`, reject duplicate `Host`
  fields, validate the bracketed-`Host` port, and add
  `Cache-Control: no-store`/`X-Content-Type-Options: nosniff` to admin responses.
- Admin bind failure: make it fatal (or force `admin_access.default: close`) and
  correct the "administrative functions stay closed" message.
- HTTP/3: reject duplicate pseudo-fields, connection-specific fields and
  `:protocol` on non-CONNECT methods at the h3 boundary; syntax-check
  `Content-Length` on every transport.
- TLS: DER-parse every certificate in the chain, cap chain count/size, and warn
  when `tls.key_file` is group/other-readable.
- `kunato log`: handle backslash escapes on `char` boundaries (panic at
  `src/logs/parse.rs:350`).
- Dependency gate: fail closed on a stale advisory DB instead of relying on
  cargo-deny's 90-day default.
- CI: run the build/test gate on ordinary pull requests, not only Dependabot;
  set `persist-credentials: false` on the PR lab job; pin `python3`/`shellcheck`.
- Upload inspection: make marker scans wide-encoding aware and inspect parts
  whose `filename` is present but empty.
- Legacy identity headers: extend the strip list to vendor scheme headers
  (`Front-End-Https`, `X-Url-Scheme`, `X-Original-Host`).
- ACME: require zero pad bits in padded base64, honor `Retry-After` in the
  same-order retry, reject not-yet-valid certificates at load, and use a
  per-directory account key.
- CVE feed ingestion: `curl --max-filesize`, decompress through a byte-counted
  cap, bound KEV/EPSS and the extraction record/output size, and cap the manual
  `--since` backfill.
- Daily-CVE allowlist: the policy gate parses only the categories block, so a
  top-level config edit is unpublished-but-committed; either restrict the
  allowlist to `rules.example.yaml` categories or validate the whole example
  file before signing.
- Continuous fuzzing for the hand-written decoders (YAML, SAML XML, DER,
  multipart, HPACK) and the `kunato log` parser.

## Second-audit verification gate

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
python3 scripts/test_check_rules_policy.py
```

Then re-run the bounded reproductions from the audit: the stalled-body
inspection budget, the HTTP/3 idle and HEADERS cases, the authority-form and
missing-`:path` targets, the GraphQL envelope, concatenated zstd, the escaped
SAML field name, the nested-`Response` assertion, the truncated SAML body, the
JWT-only body, the WebSocket content-route reload, the 20 KiB ETag rollback
replay, and the four policy-gate spellings.

## Second-audit implementation status

S-01 to S-03 (the three high findings) are implemented and covered by
regression tests. The rest of the plan is staged so the fail-closed gates land
before the ordering repair.

| ID | Status | Fix and regression evidence (to be filled in) |
|---|---|---|
| S-01 | fixed | Requests admit at zero bytes and grow only with buffered bytes (`reserve_request_inspection`, `grow_request_inspection_raw`); `stalled_request_bodies_do_not_exhaust_the_inspection_budget` and `request_inspection_charges_only_buffered_bytes` fail on the old baseline. |
| S-02 | fixed | Both h3 close paths are bounded by `connection_idle.min(1s)`; `http3_idle_connection_releases_its_slot_without_control_credit` fails on the old code (the server refuses the second connection). |
| S-03 | fixed | `src/proxy/h3_limits.rs` wraps `h3_quinn::Connection` and rejects a HEADERS frame from its declared length before h3 buffers it (five parser unit tests); `http3_rejects_an_oversized_headers_frame_before_buffering_it` fails when the guard is disabled. Remove the wrapper if a future h3 release enforces the declared frame length itself. |
| S-04 | fixed | `request_head_error` rejects an empty or non-`/` request target (asterisk-form only for `OPTIONS`), which covers the HTTP/1.1 authority-form target and the HTTP/3 head without `:path`/`:scheme`; `authority_form_request_targets_are_rejected`, `origin_and_absolute_form_targets_pass_head_validation`, `asterisk_form_is_allowed_only_for_options`, `authority_form_request_target_is_rejected_before_forwarding` and `http3_header_block_without_path_is_rejected_before_forwarding` fail on the previous behavior. |
| S-05 | fixed | `collect_json_body_queries` and `collect_json_text_queries` inspect the union of top-level and `payload.query` documents instead of selecting a branch from the attacker-supplied `type`; `rejects_a_top_level_query_hidden_behind_an_envelope`, `text_collection_inspects_envelope_and_top_level_documents` and `graphql_envelope_cannot_hide_a_top_level_query` fail on the previous behavior. |
| S-06 | fixed | `decode_zstd_all` reinitializes the decoder on the remaining input so every concatenated frame is decoded, reports `Truncated` at the output limit and `Malformed` for trailing non-frame bytes; `concatenated_zstd_frames_are_decoded`, `concatenated_zstd_frames_are_bounded`, `trailing_garbage_after_a_zstd_frame_is_malformed` and `multi_frame_zstd_request_body_is_rule_evaluated` fail on the previous single-frame decode. |
| S-07 | fixed | `has_saml_hint` is a strict superset of the field-name decoders (a literal name contains `SAML`; any escaped spelling contains `%` or `\`), so `SAM%4CResponse`, `S%41MLResponse` and `S\u0041MLResponse` reach the extractors; `mid_name_form_escapes_are_inspected`, `mid_name_json_escapes_are_inspected` and `saml_escaped_field_name_is_still_inspected` fail on the previous marker. |
| S-08 | fixed | the placement check now requires the assertion to be a direct child of the message root `<Response>`; `assertion_under_a_wrapped_response_element_is_reported`, `root_level_assertion_is_reported` and `saml_assertion_under_a_wrapped_response_is_rejected` fail on the previous immediate-parent check. |
| S-09 | fixed | `saml::inspect_truncated` returns a blocking `TooLarge` finding for a SAML-capable body cut at `max_body_bytes` (log-mode finding only under `mode: log`), before rule evaluation so `ALLOW` cannot bypass it; the documented trade-off is that over-limit form/JSON bodies are rejected while SAML strict is on. `truncated_saml_bodies_fail_closed_in_strict_mode`, `truncated_saml_bodies_are_logged_in_log_mode`, `truncated_non_saml_content_types_are_ignored` and `saml_message_past_the_inspection_prefix_is_rejected` cover it (the integration test fails on the previous behavior). |
| S-10 | fixed | an enabled `limits.jwt` now joins `inspect_body`, so supported content encodings are decoded and the strict over-limit rejection applies; `jwt_body_policy_forces_body_decoding` (gzip `text/plain` carrier, token not literal in the compressed bytes) fails on the previous behavior. |
| S-11 | fixed | the tunnel no longer captures the handshake-time `body_rules_exempt`; every message computes the exemption from the live configuration, so removing a content route re-enables body rules on open tunnels. `websocket_content_route_removal_applies_to_open_tunnels` detects a stale exemption. |
| S-12 | fixed | `scripts/check-rules-policy.py` now validates the categories block through a positive structural allowlist (canonical entry and key shapes only), so a spelling it does not recognise fails closed instead of being skipped; `scripts/test_check_rules_policy.py` covers the tab, uniform-reindent, bare-dash, nested-name and enabled-first spellings plus block-style positives, and the pristine `rules.example.yaml`/`dist/rules.yaml` still pass. |
| S-13 | fixed | `ETag`/`Last-Modified` are bounded to 512 bytes at capture, and `UpdateState::read_checked` fails closed on an oversized or unreadable state file when a trusted rules key is configured instead of treating it as a first install; `response_validators_beyond_the_state_bound_are_ignored`, `an_oversized_state_file_is_not_treated_as_a_first_install`, `an_unreadable_state_file_fails_closed` and `a_normal_state_preserves_the_signature_floor` cover it. |
| S-14 | fixed | `scripts/blackbox-test.sh` keeps the driver exit status and fails on a non-zero value; `scripts/blackbox-report.py` reconciles the parsed results with the corpus and fails an incomplete run. `scripts/test_blackbox_gate.py` covers empty, partial, complete and leaked logs plus the runner and workflow assertions. |
| S-15 | fixed | `blackbox/src/main.rs` emits its own `Host` only when the corpus supplies none and suppresses the generated framing header when the corpus declares `Content-Length`/`Transfer-Encoding`; unit tests assert exactly one of each on the affected corpus shapes. |
| S-16 | fixed | the signing job's append-only guard compares the corpus bytes with `git show HEAD:<path>` and requires a true prefix append, so a binary-classified diff cannot hide deletions; `scripts/test_blackbox_gate.py` asserts the workflow uses the byte comparison. |
| W-01 | fixed | the verify job runs `cargo test --locked -- --skip the_committed_rules_signature_is_valid` because it holds an unsigned regenerated candidate; the sign job verifies the new signature against the embedded rules key, the test still runs in normal CI, `docs/release-signing.md` records the ordering, and `scripts/test_blackbox_gate.py` asserts the skip flag. |
| L-01 | fixed | `canonical_host` resolves Unicode dot variants and inet_aton numeric forms (decimal, octal, hex, mixed, shortened) before the `internal_hosts`/`internal_suffixes` comparison; `numeric_host_spellings_are_canonicalized`, `unicode_dot_hosts_are_canonicalized`, `a_host_that_is_not_an_address_keeps_its_spelling` and `request_hardening_canonicalizes_numeric_internal_hosts` fail on the previous string comparison. Owner still confirms the upstream fetcher resolves the same forms. |
| L-02 | fixed | `duplicate_parameter` and `redirect_target` iterate every `query_forms` entry instead of the raw form only, so an encoded pair separator or name is found after the second pass; `redirects_are_found_in_every_query_decoding_pass`, `duplicates_are_found_in_every_query_decoding_pass` and `request_hardening_inspects_every_query_decoding_pass` fail on the previous first-form check. |
| L-03 | fixed | `run_init` writes through `write_config_atomic` (`symlink_metadata` check, `create_new` temp 0640, fsync, rename, directory fsync) instead of `exists()` + `std::fs::write`, and refuses a symlink or non-regular output even with `--force`; `init_refuses_to_follow_a_symlinked_output`, `init_refuses_a_dangling_symlink`, `init_overwrites_a_regular_file_only_with_force` and `init_creates_a_missing_file` cover it. |
