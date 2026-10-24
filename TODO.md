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
- Current: **99** (-106).
- Reference only: `Cargo.lock` contains 165 package entries (283 at the start).
  This counts all platforms and duplicate versions and is not the KPI.

`deny.toml` uses `[graph] all-features = true`, so Cargo feature-gating alone
does not reduce the set of monitored crates. A crate leaves the KPI only when
its dependency edge is removed or replaced by in-tree code.

## Completed

Changes 1-8 are committed. Change 9 is implemented in the working tree on
branch `remove-granit-parser`; its commit is pending. Change 8 is `586234c`;
change 5 is `b70f37c`, change 6 is `c4d23e8`, and change 7 is `bd73060`.

| # | Change | Commit | KPI after | Removed from the Linux tree | Tradeoffs / notes |
|---|--------|--------|----------:|-----------------------------|-------------------|
| 1 | `notify` -> mtime polling | `2144073` | 205 -> 199 (-6) | notify, notify-types, inotify, inotify-sys, walkdir, same-file | Reload latency is now up to 2 s; polling-only watcher; end-to-end polling test added. |
| 2 | `sha2` -> `ring` | `6c9a644` | 199 -> 192 (-7) | sha2, digest, block-buffer, crypto-common, hybrid-array, typenum, const-oid | `ring` was already in the tree; added as a direct dependency. NIST vectors cover empty input, `abc`, and 55/56/64-byte boundaries. |
| 3 | `clap` -> in-house parser | `f3d652e` | 192 -> 180 (-12) | clap, clap_builder, clap_derive, clap_lex, anstream, anstyle-parse, anstyle-query, colorchoice, heck, is_terminal_polyfill, strsim, utf8parse | New [src/cli/parse.rs](src/cli/parse.rs); 17 parser tests. Help and error wording is not byte-identical to clap. |
| 4 | `tracing-subscriber` -> in-tree logging | `64c675f` | 180 -> 173 (-7) | tracing-subscriber, matchers, nu-ansi-term, sharded-slab, thread_local, tracing-log, tracing-serde | New [src/telemetry/](src/telemetry/); 22 tests. Filter supports `level` and `target=level`; span/field directives are unsupported. `log` records from dependencies are bridged. |
| 5 | `tokio-rustls-acme` -> in-tree ACME client | `b70f37c` | 173 -> 112 (-61) | tokio-rustls-acme, async-trait, reqwest, rcgen, x509-parser, chrono, url/ICU4X, tower, and their support crates | New [src/acme/](src/acme/); RFC 8555 with TLS-ALPN-01, ECDSA P-256 CSR/challenge-certificate DER, renewal at two thirds of validity, and cached account/certificate material. Pebble issuance, renewal, HTTP/3, and cache-reuse tests pass. `rcgen`/`x509-parser` remain dev-only. |
| 6 | ACME review hardening | `c4d23e8` | 112 -> 112 (0) | none | Hardened cache temp files against symlink redirection, validated cached certificates against domains, directory, and expiry, accepted private-CA critical extensions through the SPKI fallback, honoured `Retry-After`, batched multi-domain authorization polling, rejected duplicate domains, bounded HTTP bodies/log strings/chain size, and added unit and multi-domain Pebble tests plus a nightly Pebble workflow. |
| 7 | ACME origin and order resilience | `bd73060` | 112 -> 112 (0) | none | Restricted response-supplied ACME URLs to the directory origin plus an optional `tls.acme.allowed_origins` list; transient order failures are retried against the same order before starting a new one. |
| 8 | `serde-saphyr` -> `granit-parser` + in-tree serde deserializer | `586234c` | 112 -> 101 (-11) | serde-saphyr, annotate-snippets, anstyle, unicode-width, encoding_rs_io, encoding_rs, core_detect, multiversion_no_op, scopeguard, simdutf8, num-traits | New [src/yaml/](src/yaml/); YAML 1.2 syntax from `granit-parser`, serde mapping in-tree. Anchors, aliases, merge keys, explicit tags, directives, and multiple documents are rejected; error rendering and locations differ from `serde-saphyr`. 514 unit tests and all integration tests pass; a typical 89 KB file parses in about 1.8 ms with a 3 MB peak. |
| 9 | `granit-parser` -> in-tree YAML subset parser | pending | 101 -> 99 (-2) | granit-parser, arraydeque | New [src/yaml/parser.rs](src/yaml/parser.rs); YAML syntax parsing is now fully in-tree. Flow collections and quoted scalars must be on one line; block scalars, multi-line plain scalars, comments, and compact block collections are supported. The new parser matched the previous parser on 89 corpus documents before removal. 520 unit tests and all integration tests pass. |

Platform-specific crates also disappear from `Cargo.lock` (for example
`fsevent-sys`, `kqueue`, `anstyle-wincon`, `once_cell_polyfill`, and
`valuable`); the table lists only the Linux production tree. The `log` crate
became a direct dependency in change 4 but was already in the tree, so the KPI
did not increase. Change 5 removed 60 names from the production tree plus
`async-trait`; `rcgen` and `x509-parser` remain in the lock file as dev-only
dependencies used by the certificate tests.

Change 8 removes 11 names from the production tree. `num-traits` remains in
`Cargo.lock` as a dev-only dependency of `rcgen`/`x509-parser`, like those two
crates. Change 9 removes `granit-parser` and its `arraydeque` dependency, which
change 8 had retained.

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
- Configuration and rule files are parsed by the in-tree YAML parser and
  deserializer in [src/yaml/](src/yaml/). Anchors, aliases, merge keys, explicit
  tags, directives, and multiple documents are rejected; block scalars,
  multi-line plain scalars, and comments are supported. Flow collections and
  quoted scalars must be on one line, and document markers must be on their own
  line.
- YAML parse errors keep serde's unknown-field, unknown-variant, and
  missing-field classification for rule-set compatibility, but the wording and
  snippet rendering are in-tree.

## Backlog

Priority is KPI impact divided by effort and risk. Re-measure the KPI before
starting each item: removing one dependency can change the savings of another.

| Priority | Candidate | KPI impact | Effort | Risk | Decision |
|----------|-----------|-----------:|--------|------|----------|
| 2 | Drop HTTP/3 (`h3`, `h3-quinn`, `quinn`) | -16 | M | Product regression | **Retained** by product decision (2026-10-24); do not remove. |
| 3 | `flate2` -> in-house DEFLATE | -5 | L | High | Not recommended. A partial replacement (`miniz_oxide` plus in-house gzip/zlib framing) would save roughly 3, not 5. |
| 4 | `brotli-decompressor` -> in-house Brotli | -3 | XL | High | Not recommended. |
| 5 | `ruzstd` -> in-house Zstandard | -2 | XL | High | Not recommended. |
| 6 | `arc-swap` -> `RwLock<Arc<T>>` wrapper | -2 | S-M | Medium | Defer; conflicts with the lock-free config snapshot design. |
| 7 | `regex` -> in-house regex engine | -3 | XL | Very high | Not worth it. |
| - | Direct-only crates: `thiserror`, `futures-util`, `ipnet`, `rustls-native-certs`, `serde_json`, `regex-syntax`, `hyper-rustls` | 0 | S-L | Low-medium | Out of KPI scope; they remain transitive through other dependencies. |
| - | Dev-only edges: `tempfile`, `brotli`, `rcgen`, `x509-parser`, `rustix`, `linux-raw-sys` | 0 | S-M | Low | Not KPI; do not prioritize. |

`rcgen` and `x509-parser` are now dev-only; the production tree no longer
contains either crate. Priority 1 (`serde-saphyr`) and its follow-up
(`granit-parser`) are complete; see changes 8 and 9.

### Notes on the backlog

- **YAML (done):** see changes 8 and 9. The supported subset is documented in
  [docs/development.md](docs/development.md); the design record is in
  [docs/serde-saphyr-replacement-spike.md](docs/serde-saphyr-replacement-spike.md).
- **HTTP/3 (-16):** retained by product decision on 2026-10-24. The measured
  saving is 16 names, not 14; the item stays closed unless the decision changes.
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

1. Review and commit change 9 on branch `remove-granit-parser`; the KPI is 99.
   The full test suite, clippy, and the dependency audit pass.
2. No further dependency work is recommended. Compression, regex, and `arc-swap`
   remain closed for the reasons above, and HTTP/3 is retained by product
   decision (2026-10-24).

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
