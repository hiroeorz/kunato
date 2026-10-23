# Dependency Reduction TODO

Last updated: 2026-10-24

Goal: remove external crates from the production dependency graph, replacing
narrowly used functionality with small in-tree implementations where practical.
New dependencies require justification; prefer the standard library.

## KPI

**Definition:** the number of distinct external crate names in the Linux
production tree (default features), excluding the local `kunato` package.
Test-only and dev-dependencies do not count. If one crate appears with multiple
versions, it is counted once.

Measurement:

```sh
cargo tree --offline -e normal --target x86_64-unknown-linux-gnu --prefix none \
  | sed 's/^[│├└─ ]*//' | awk '{print $1}' | sort -u \
  | grep -v '^kunato$' | wc -l
```

- Start: **205**
- Current: **112** (-93)
- Reference only: `Cargo.lock` contains 177 package entries (283 at the start).
  This counts all platforms and duplicate versions and is not the KPI.

`deny.toml` uses `[graph] all-features = true`, so Cargo feature-gating alone
does not reduce the set of monitored crates. A crate leaves the KPI only when
its dependency edge is removed or replaced by in-tree code.

## Completed

Changes 1-5 were completed and committed on 2026-10-23. Change 5 is
`b70f37c`; the follow-up review fixes are in the working tree.

| # | Change | Commit | KPI after | Removed from the Linux tree | Tradeoffs / notes |
|---|--------|--------|----------:|-----------------------------|-------------------|
| 1 | `notify` -> mtime polling | `2144073` | 205 -> 199 (-6) | notify, notify-types, inotify, inotify-sys, walkdir, same-file | Reload latency is now up to 2 s; polling-only watcher; end-to-end polling test added. |
| 2 | `sha2` -> `ring` | `6c9a644` | 199 -> 192 (-7) | sha2, digest, block-buffer, crypto-common, hybrid-array, typenum, const-oid | `ring` was already in the tree; added as a direct dependency. NIST vectors cover empty input, `abc`, and 55/56/64-byte boundaries. |
| 3 | `clap` -> in-house parser | `f3d652e` | 192 -> 180 (-12) | clap, clap_builder, clap_derive, clap_lex, anstream, anstyle-parse, anstyle-query, colorchoice, heck, is_terminal_polyfill, strsim, utf8parse | New [src/cli/parse.rs](src/cli/parse.rs); 17 parser tests. Help and error wording is not byte-identical to clap. |
| 4 | `tracing-subscriber` -> in-tree logging | `64c675f` | 180 -> 173 (-7) | tracing-subscriber, matchers, nu-ansi-term, sharded-slab, thread_local, tracing-log, tracing-serde | New [src/telemetry/](src/telemetry/); 22 tests. Filter supports `level` and `target=level`; span/field directives are unsupported. `log` records from dependencies are bridged. |
| 5 | `tokio-rustls-acme` -> in-tree ACME client | `b70f37c` | 173 -> 112 (-61) | tokio-rustls-acme, async-trait, reqwest, rcgen, x509-parser, chrono, url/ICU4X, tower, and their support crates | New [src/acme/](src/acme/); RFC 8555 with TLS-ALPN-01, ECDSA P-256 CSR/challenge-certificate DER, renewal at two thirds of validity, and cached account/certificate material. Pebble issuance, renewal, HTTP/3, and cache-reuse tests pass. `rcgen`/`x509-parser` remain dev-only. |
| 6 | ACME review hardening | uncommitted | 112 -> 112 (0) | none | Hardened cache temp files against symlink redirection, validated cached certificates against domains, directory, and expiry, accepted private-CA critical extensions through the SPKI fallback, honoured `Retry-After`, batched multi-domain authorization polling, rejected duplicate domains, bounded HTTP bodies/log strings/chain size, and added unit and multi-domain Pebble tests plus a nightly Pebble workflow. |

Platform-specific crates also disappear from `Cargo.lock` (for example
`fsevent-sys`, `kqueue`, `anstyle-wincon`, `once_cell_polyfill`, and
`valuable`); the table lists only the Linux production tree. The `log` crate
became a direct dependency in change 4 but was already in the tree, so the KPI
did not increase. Change 5 removed 60 names from the production tree plus
`async-trait`; `rcgen` and `x509-parser` remain in the lock file as dev-only
dependencies used by the certificate tests.

### Behavior changes to remember

- Configuration reload is polling-based (2 s), not event-based.
- CLI help and parse errors are generated in-tree; wording differs from clap.
- The log filter supports `level` and `target=level` directives, not span or
  field directives. JSON key order may differ; the schema is unchanged.
- Text logs color the level only when stdout is a terminal and `NO_COLOR` is
  unset.
- ACME is now an in-tree client. `cert.pem` (private key plus chain) and
  `account.key` (raw PKCS#8) keep their previous formats, so an existing cache
  is reused after an upgrade.
- The ACME driver waits for the proxy listener to be bound before ordering, so
  the CA can always reach the TLS-ALPN-01 endpoint.
- ACME retry backoff starts at 1 s and caps at 1 h. The client connects
  directly; outbound proxy environment variables and directory redirects are
  not used.

## Backlog

Priority is KPI impact divided by effort and risk. Re-measure the KPI before
starting each item: removing one dependency can change the savings of another.

| Priority | Candidate | KPI impact | Effort | Risk | Decision |
|----------|-----------|-----------:|--------|------|----------|
| 1 | `serde-saphyr` -> in-house YAML 1.2 | -12 | XL | High | Defer until a parser design and compatibility corpus exist. |
| 2 | Drop HTTP/3 (`h3`, `h3-quinn`, `quinn`) | -14 | M | Product regression | Only with an explicit product decision. |
| 3 | `flate2` -> in-house DEFLATE | -5 | L | High | Not recommended. A partial replacement (`miniz_oxide` plus in-house gzip/zlib framing) would save roughly 3, not 5. |
| 4 | `brotli-decompressor` -> in-house Brotli | -3 | XL | High | Not recommended. |
| 5 | `ruzstd` -> in-house Zstandard | -2 | XL | High | Not recommended. |
| 6 | `arc-swap` -> `RwLock<Arc<T>>` wrapper | -2 | S-M | Medium | Defer; conflicts with the lock-free config snapshot design. |
| 7 | `regex` -> in-house regex engine | -3 | XL | Very high | Not worth it. |
| - | Direct-only crates: `thiserror`, `futures-util`, `ipnet`, `rustls-native-certs`, `serde_json`, `regex-syntax`, `hyper-rustls` | 0 | S-L | Low-medium | Out of KPI scope; they remain transitive through other dependencies. |
| - | Dev-only edges: `tempfile`, `brotli`, `rcgen`, `x509-parser`, `rustix`, `linux-raw-sys` | 0 | S-M | Low | Not KPI; do not prioritize. |

`rcgen` and `x509-parser` are now dev-only; the production tree no longer
contains either crate.

### Notes on the backlog

- **YAML (-12):** configuration and rule parsing are security-critical. An
  in-house parser needs YAML 1.1/1.2 feature coverage, duplicate-key and anchor
  policy, error locations, and a corpus of real configurations and rule sets.
  Do not start without a design and test plan.
- **HTTP/3 (-14):** this is a feature removal, not a replacement. It changes
  the supported protocol surface and the `http3` configuration field.
- **Compression (-10 total):** decompression handles untrusted request bodies.
  An in-house decoder must preserve the existing size limits, streaming
  behavior, and malformed-input handling. High risk, low KPI gain.
- **`arc-swap` (-2):** a `std::sync::RwLock<Arc<T>>` wrapper is simple, but it
  adds a lock to the request hot path and contradicts the documented lock-free
  snapshot design.
- **Direct-only removals:** these crates would remain in the tree through other
  dependencies (mostly `quinn`, `hyper-util`, and `hyper-rustls`), so the KPI
  would not move.

## Recommended next step

1. The ACME replacement is committed as `b70f37c`; review the hardening changes
   in the working tree, commit them, and refresh the change 6 row with the new
   commit hash (the KPI remains 112).
2. If dependency work continues, start a **`serde-saphyr` design spike** (-12):
   enumerate the YAML features used by `rules.example.yaml` and the
   configuration schema, then decide on an in-house parser.
3. Do not start compression or regex work unless the KPI target changes. The
   HTTP/3 removal (-14) remains a product decision.

## Definition of done (per item)

- Before/after KPI measured with the command above.
- The production dependency edge is removed; test-only and dev-only crates are
  not counted as progress.
- `cargo fmt`
- `cargo clippy --all-targets -- -D warnings`
- `./scripts/check-deny.sh`
- `cargo test`
- [docs/DESIGN.md](docs/DESIGN.md) dependency table and behavior notes updated.
- This file updated: commit hash, KPI before/after, removed packages, tradeoffs.
- Commit message in English, imperative, and justifies the dependency change.
- Security-sensitive replacements include test vectors and malformed-input
  tests; design invariants (bounded resources, no panics on request paths) are
  not weakened.
