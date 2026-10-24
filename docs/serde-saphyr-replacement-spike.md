# Replacing `serde-saphyr`: design spike and recommendation

Date: 2026-10-24

Status: implemented in commit `586234c`. This file is retained as the design
and decision record.

Follow-up (change 9): the retained `granit-parser` and `arraydeque` dependency
was later removed in commit `07f6028` by replacing the event parser with an
in-tree parser in [`../src/yaml/parser.rs`](../src/yaml/parser.rs). The YAML
subset is unchanged
except that flow collections and quoted scalars are limited to one line. The
KPI is now 99. The sections below describe the first step (change 8).

## Summary

**Implemented: a direct `granit-parser` dependency plus an in-tree serde
deserializer.** `granit-parser` was already in the production dependency tree as
`serde-saphyr`'s YAML parser, so this replaced the large deserialization crate
without adding a new crate to the graph.

| | |
|---|---|
| KPI | 112 -> **101** (-11) |
| Effort | L, roughly 8-12 working days |
| Risk | Medium |
| Removed crates | `serde-saphyr`, `annotate-snippets`, `anstyle`, `unicode-width`, `encoding_rs_io`, `encoding_rs`, `core_detect`, `multiversion_no_op`, `scopeguard`, `simdutf8`, `num-traits` |
| Retained | `granit-parser`, `arraydeque` (already transitive; removed by change 9) |

Implementation result (change 8): the KPI was 101, `serde-saphyr` is no longer
in the production graph, and 514 unit tests plus all integration tests pass. The
production deserializer lives in [`../src/yaml/`](../src/yaml/); its unit tests
cover the scalar matrix, duplicate keys, unsupported constructs, error
locations, and a deterministic mutation pass over the rule set.

The alternative, writing a full YAML 1.2 parser in-tree, removes two more
crates (`granit-parser`, `arraydeque`) for -13 KPI but is XL effort and high
risk. It was not recommended while `granit-parser` was available and tested
against the YAML test suite. Change 9 revisited this after the deserializer made
the remaining parser work smaller.

The design was validated with a scratch prototype (not committed; see
`target/yaml-spike/`):

- deserializes the real `ConfigSpec` and `RulesFileSpec`;
- deserializes a synthetic configuration that exercises every field type
  (`SocketAddr`, `PathBuf`, `Duration`, `u8`, `usize`, `f64`, all enums,
  untagged helpers, and custom deserializers);
- parses the current `rules.example.yaml` and all 42 git revisions of it;
- parses all 25 git revisions of `dist/rules.yaml`;
- parses all 20 YAML fences in `docs/` and `README.md`;
- classifies unknown fields, unknown variants, and missing fields exactly as
  required by rule-set compatibility;
- reproduces `serde-saphyr` 1.3.0's scalar coercion and untagged semantics for
  the cases measured;
- parses the 89 KB `rules.example.yaml` in about 1.8 ms with a 3 MB peak RSS.

The prototype's sixteen tests passed; the production implementation adds its own
unit tests and is exercised by the full suite.

## Decisions and status

The proposed path was approved and implemented:

1. Direct `granit-parser` dependency: adopted.
2. Supported YAML subset (anchors, aliases, merge keys, explicit tags,
   directives, and multiple documents rejected): adopted and documented in
   [`development.md`](development.md).
3. Value-tree memory bound (about 127 MB at 1,000,000 nodes; typical files a few
   MB): accepted. A streaming deserializer remains a possible follow-up.

Committed as `586234c`.

## State before the change

`serde-saphyr` was used at five call sites:

- `src/config/mod.rs`: `read_spec`, `load_candidate`, `parse`, `parse_rules`,
  and `load_rules_spec` (`serde_saphyr::from_str`). All five now call
  `crate::yaml::from_str`.
- `src/error.rs`: `ConfigParse` and `RulesParse` carried
  `serde_saphyr::Error`, and `unsupported_construct` matched
  `SerdeUnknownField`, `SerdeUnknownVariant`, and `SerdeMissingField`. They now
  carry `crate::yaml::Error` and use its `is_unsupported_construct` and
  `summary` methods.
- `src/rules_update.rs`: maps an unsupported construct to
  `RulesNeedNewerBuild` so an old binary keeps its last good rule set. This path
  is unchanged.

The configuration schema uses:

- 25 `deny_unknown_fields` sites;
- 4 `untagged` enums (`StatusItem`, `StatusItems`, `StringOrSeq`,
  `DurationValue`);
- 4 custom deserializers (`de_duration`, `de_allowed_hosts`,
  `de_opt_string_or_seq`, `de_opt_statuses`);
- renamed fields, defaults, maps, sequences, and unit enums.

`src/config/mod.rs` has 105 unit tests. The suite has to keep passing unchanged;
only the parser behind `config::parse` / `config::parse_rules` changes.

## YAML feature inventory

Method: PyYAML event scan over 86 unique documents (current rule files, 42
`rules.example.yaml` revisions, 25 `dist/rules.yaml` revisions, and 20 YAML
fences from `docs/` and `README.md`), plus a scan of inline YAML in `src/` and
`tests/`.

| Feature | Used | Notes |
|---|---|---|
| Block mappings and sequences | Yes | Primary style for configuration |
| Flow mappings and sequences | Yes | `match: { ... }`, `in: [query, body]` |
| Plain scalars | Yes | Names, paths, regexes, numbers, enums |
| Single-quoted scalars | Yes | Most regexes; 34k+ events |
| Double-quoted scalars | Yes | 68 events, mostly regexes with escapes |
| Comments | Yes | Top-level and inline |
| Block scalars (`|`, `>`) | No | Supported by the proposed parser for free |
| Multi-line plain scalars | No | Supported by `granit-parser` |
| Anchors and aliases | No | Rejected in the proposal |
| Merge keys (`<<`) | No | Rejected; no merge semantics |
| Explicit tags (`!!str`, ...) | No | Rejected |
| Directives (`%YAML`, `%TAG`) | No | Rejected |
| Multiple documents | No | Rejected, matching `serde_saphyr::from_str` |
| CRLF, BOM, tab indentation | No | `granit-parser` handles CRLF and BOM |

The corpus uses no construct that the proposed subset would reject.

## Required semantics

The following behavior of `serde-saphyr` 1.3.0 with default options was measured
and reproduced by the prototype. It is the compatibility contract for the new
parser.

### Scalar resolution

| Target | `404` (plain) | `'404'` (quoted) | Notes |
|---|---|---|---|
| `deserialize_any` | integer 404 | string `"404"` | Used by untagged enums |
| `String` | `"404"` | `"404"` | Raw source spelling: `0x10` stays `"0x10"` |
| `u64` | 404 | 404 | `0x`, `0o`, `0b`, `_`; legacy octal `0123` rejected |
| `bool` | - | - | `true/false`, `yes/no`, `y/n`, `on/off`, case-insensitive; quoted accepted; numbers rejected |
| `f64` | 404.0 | 404.0 | `.inf`/`.nan` accepted for typed targets |
| Unit enum | `BLOCK` | `BLOCK` | Quoted variant names accepted |
| `Option<T>` | - | `"null"` is a string | Plain empty/`~`/`null` is `None` |

Additional requirements:

- `deserialize_any` resolves a plain scalar to bool, integer, float, or null in
  that order; otherwise it is a string. `0123` resolves to the float 123.0
  because it is not a valid integer; non-finite floats are rejected for
  `deserialize_any`.
- `String` targets receive the raw scalar spelling, not a canonical number.
- Null into a non-`Option` `String` is an error with a location.
- Empty input is an error (`unexpected end of input`), matching
  `serde_saphyr::from_str`; `parse_rules` handles empty files before calling the
  parser.
- Duplicate mapping keys are an error. Key equality is type-aware: `1` and
  `0x1` are duplicates, `1` and `'1'` are not.
- Multiple documents are rejected.

### Unsupported constructs

The following are rejected with a located error instead of being silently
reinterpreted:

- anchors and aliases (prevents alias-expansion bombs);
- merge keys;
- explicit tags, including `!!str`;
- YAML directives;
- multiple documents.

None appear in the repository, documentation, or the 67 historical rule files.
The release notes must call this out because `serde-saphyr` accepted anchors,
aliases, and merge keys.

## Error compatibility

`unsupported_construct` is the contract that lets an older binary distinguish a
newer rule-set format from a broken download. The new error type exposes:

```rust
pub enum ErrorKind {
    Syntax,
    UnknownField,
    UnknownVariant,
    MissingField,
    Message,
}
```

`Error::unsupported_construct` becomes a match on
`UnknownField | UnknownVariant | MissingField`. The three existing tests in
`src/error.rs` and the rule-update integration test keep their meaning. The
message keeps the `unknown field \`x\`, expected ...` / `missing field \`x\`` /
`unknown variant \`x\`, expected ...` shape, including the field or variant name
that the rule-update log reports.

No test asserts a snippet, a line number, or a `-->` marker. Two tests assert
that an error contains `unknown`; the new messages satisfy both.

### Locations and snippets

- Syntax errors use the `granit-parser` marker (line and column).
- Typed scalar errors (invalid boolean, integer, or float) use the scalar's
  location.
- Schema errors (`unknown_field`, `missing_field`, `unknown_variant`) are
  created by serde derive without a location. The implementation will keep a
  thread-local fallback location set by map and enum access, so these errors
  still point at the offending key or mapping. Parsing is synchronous per
  thread, so a thread-local is safe and does not affect the request path.
- `Display` renders `message at line N, column M` and a cropped source line
  with a caret. This is a small in-tree renderer, not the `annotate-snippets`
  output; message text and locations remain useful, but the exact rendering
  changes.

## Options

| Option | KPI | Effort | Risk | Assessment |
|---|---:|---|---|---|
| A. Full in-house YAML 1.2 parser + serde layer | -13 | XL | High | Not recommended; would need a parser design, test suite, and fuzzing while `granit-parser` already exists |
| B. `granit-parser` + in-tree serde layer | -11 | L | Medium | **Recommended** |
| C. Keep `serde-saphyr` | 0 | None | None | Acceptable fallback if the unsupported-feature policy is unacceptable |
| D. Swap in another YAML crate | ~0 | L | Medium | Does not reduce the KPI and changes the schema dependency |

Option B keeps the syntax parser (the hard, security-sensitive part) in a
crate that forbids unsafe code, is fuzz-tested, and follows the YAML test suite.
The in-tree part is the mapping from YAML nodes to serde, which the existing
schema and tests can validate directly.

## Proposed architecture

```text
src/yaml/
  mod.rs      # pub(crate) from_str<T>, parse_value, Error re-export
  value.rs    # Scalar/Value tree, scalar resolution, limits
  de.rs       # serde Deserializer for Value
  error.rs    # Error, ErrorKind, Display and snippet, serde::de::Error
```

- `from_str` builds a `Value` tree with `granit-parser`, then calls
  `T::deserialize(value)`.
- `Value` preserves scalar spelling and style, collection order, and duplicate
  keys. A map is a `Vec<(Value, Value)>`, so serde sees every key and derive can
  report duplicate fields.
- Comment emission is disabled in `granit-parser` options; comments are
  recognized but not allocated.
- Limits: nesting depth 128, node count 1,000,000. The caller already caps
  configuration files at 16 MiB and downloaded rule sets at `max_bytes`.
- No `unsafe`, no panics on untrusted input, no alias expansion.
- `granit-parser` is wrapped only in this module; a future version change does
  not touch configuration or rule code.

### Why a value tree rather than a streaming deserializer

A value tree is smaller and simpler to test, and it gives untagged enums the
`deserialize_any` behavior they need without a second deserializer. The cost is
memory amplification: each scalar is owned. Measured peak RSS is about 3 MB for
the 89 KB `rules.example.yaml` and about 127 MB when the 1,000,000-node cap is
reached. Typical deployments stay far below that. If the worst-case bound
becomes a concern, a later streaming deserializer can replace the tree without
changing the schema or the public API.

## Prototype evidence

Location: `target/yaml-spike/` (gitignored scratch project; disposable).

Core size: about 1,000 lines (`value.rs` plus `de.rs`), of which the production
implementation should keep most of the design but not the prototype's
`expect` calls. Sixteen tests cover:

- real `ConfigSpec` deserialization for `rules.example.yaml`;
- every field type through a synthetic full configuration;
- real `RulesFileSpec` for the current and all historical `dist/rules.yaml`;
- all historical `rules.example.yaml` revisions through the current
  `ConfigSpec`;
- all 20 documentation YAML fences;
- untagged, `deny_unknown_fields`, renamed fields, maps, and sequences;
- scalar coercion and duplicate-key behavior;
- unknown field, unknown variant, and missing field classification;
- duplicate keys, anchors, aliases, tags, and multiple documents;
- flow, comments, block scalars, and syntax-error locations.

Performance was measured with a release build:

| Input | Size | Nodes | Time | Peak RSS |
|---|---:|---:|---:|---:|
| `rules.example.yaml` | 89 KB | 5,526 | 1.8 ms | 3 MB |
| synthetic rule set | 16 MiB | >1,000,000 (rejected) | 0.3 s | 127 MB |

The synthetic file had about 59,000 categories, far beyond any realistic rule
set; it was rejected at the node cap. A realistic 16 MiB rule set is about
one million nodes and would sit at the same bound.

The prototype is not production code: schema errors currently have no
location, the snippet renderer is not implemented, and no fuzz harness has run
yet. These are implementation tasks, not open design questions.

## Migration plan

1. Add `granit-parser` as a direct dependency (it is already in the graph; no
   KPI change at this step).
2. Add `src/yaml/` with the value tree, deserializer, error type, and unit
   tests, without changing call sites.
3. Add `serde-saphyr` as a **dev-dependency** and a differential test that parses
   the corpus into `serde_json::Value` with both parsers and compares the
   results for supported constructs. Also compare error classification for
   unknown fields, variants, and missing fields.
4. Switch the five call sites and the two error variants. Update
   `unsupported_construct`. Run the full test suite.
5. Remove the `serde-saphyr` dependency and the differential test dependency;
   re-measure the KPI (expected 101).
6. Update `docs/DESIGN.md` (dependency table), this TODO file, and the release
   notes for the unsupported YAML constructs.

Rollback is a revert of one change: no files, caches, or wire formats change.
The parser is only used at configuration load and rules-update validation.

## Test plan

- Existing suite: all 105 configuration unit tests and integration tests pass
  unchanged.
- Corpus: current `rules.example.yaml`, `dist/rules.yaml`, documentation fences,
  and synthetic edge cases. Historical git revisions are a local verification
  step; CI may use a shallow clone, so the test must not depend on full history.
- Differential: for every corpus document, parse with `serde-saphyr` and with
  the new parser into `serde_json::Value` and compare. Compare error kinds for
  typed failures.
- Rule-set compatibility: `tests/rules_update.rs` and
  `scripts/check-rules-compat.sh` continue to pass; an unknown field still maps
  to `RulesNeedNewerBuild`.
- Fuzz/robustness: deterministic mutation and truncation of corpus documents,
  asserting that parsing returns instead of panicking; optional `cargo-fuzz`
  target for deeper coverage.
- Resource bounds: tests for depth, node count, duplicate keys, and unsupported
  constructs.
- Performance: a manual benchmark; avoid a flaky CI timing assertion.

## Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scalar or untagged mismatch | Medium | Medium | Differential corpus, scalar matrix tests, existing suite |
| Schema error locations regress | Medium | Low | Thread-local fallback; tests for line/column |
| Unsupported YAML breaks a user config | Low | Medium | Release notes; no in-repo or historical usage; clear error |
| Memory amplification on huge files | Low | Medium | 1M-node cap; measured bound; streaming deserializer as follow-up |
| `granit-parser` API churn | Low | Low | Wrapper module; pinned lockfile; upstream is actively maintained |
| In-tree deserializer maintenance | Medium | Low | Small surface, serde contract, extensive tests |
| Hidden test failures | Medium | Medium | Prototype exercises the real schema; run the full suite before removing `serde-saphyr` |

## Effort

| Work | Days |
|---|---:|
| Value tree, scalar resolution, deserializer, error type | 4-6 |
| Call-site integration and full-suite fixes | 2-3 |
| Differential, corpus, fuzz, performance hardening | 2-3 |
| Documentation and release notes | 1 |
| Total | 8-12 |

## Go / no-go (result)

The change was implemented. Items 1, 2 (corpus validation), 3, 5, and 6 hold;
the deterministic mutation test covers the panic check at unit-test scale. A
full fuzz target remains a follow-up.

The original conditions were:

Proceed if all of the following hold:

1. The existing suite passes after the call-site switch, with no behavior change
   beyond the documented unsupported constructs.
2. Differential parsing of the corpus matches for supported constructs.
3. The rule-set compatibility path still classifies unknown fields, variants,
   and missing fields.
4. Mutation/fuzz testing finds no panic.
5. Peak memory at the node cap is acceptable (about 127 MB measured).
6. The direct `granit-parser` dependency is approved.

Stop and keep `serde-saphyr` if scalar mismatches require large compatibility
shims, if schema error quality is unacceptable, or if the maintainer does not
want a direct parser dependency. In that case the full in-house parser is the
only remaining path to a lower KPI, and it is a separate XL project.

## Open questions (resolved)

- Direct `granit-parser` dependency and -11 rather than the -13 full parser:
  adopted.
- Rejecting anchors, aliases, merge keys, explicit tags, and multiple documents:
  adopted; see [`development.md`](development.md).
- About 127 MB peak RSS at the pathological node cap: accepted. A streaming
  deserializer remains a follow-up if the bound becomes a problem.
- Differential `serde-saphyr` dev-dependency: not retained. The scalar matrix is
  pinned by unit tests, and the full suite is the acceptance oracle.

## Appendix: KPI accounting

Measurement command (from `TODO.md`):

```sh
cargo tree --offline -e normal --target x86_64-unknown-linux-gnu --prefix none \
  | sed 's/^[│├└─ ]*//' | awk '{print $1}' | sort -u \
  | grep -v '^kunato$' | wc -l
```

- Before: 112.
- Implemented (option B): 101.
- Option A (not implemented): 99.

Option B removes the crates listed in the summary and retains `granit-parser`
and `arraydeque`, which are already in the production tree. Option A would also
remove those two and requires a full YAML 1.2 parser.
