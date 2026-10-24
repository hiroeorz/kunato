# HTTP/3 stack in-house implementation assessment

Status: **Assessment — not recommended.** No implementation is planned.

This document evaluates replacing the HTTP/3 stack (`h3`, `h3-quinn`, and
`quinn`) with in-tree code. It records the measured dependency impact, the
implementation surface, the security and interoperability risks, and the
alternatives. The recommendation is to keep the current crates.

## 1. Summary

Removing all three crates would lower the KPI by 18 names, from 95 to 77. That
is the same saving as dropping HTTP/3, which the project retained by product
decision on 2026-10-24.

An in-house replacement would not be a dependency cleanup. It would be a new,
internet-facing implementation of QUIC and HTTP/3:

- about **59,300 lines** of Rust in the five crates' `src/` trees (including
  inline tests and comments);
- for comparison, the entire `src/` tree of Kunato is about **32,200 lines**
  and the HTTP/3 adapter in `src/proxy/http3.rs` is **406 lines**;
- the QUIC layer alone (QUIC transport, loss recovery, congestion control, UDP
  I/O, TLS integration) is about **39,200 lines** and 11 of the 18 removed
  names;
- the HTTP/3 layer (framing, QPACK, request/response lifecycle) is about
  **20,100 lines** and 7 names.

The earlier ACME replacement removed 61 names with about 3,300 lines of in-tree
code. The HTTP/3 stack would remove 18 names with about 59,300 lines: roughly
60 times more code per crate removed. That comparison is not exact (the ACME
change replaced a dependency with a particularly heavy subtree), but the order
of magnitude is decisive.

Not every line would be reimplemented. A server-only subset can omit 0-RTT,
server push, datagrams, WebTransport, and active connection migration. Those
omissions reduce the surface, but packet protection, loss recovery, congestion
control, flow control, stream state, and QPACK remain; a subset that works with
browsers would still be tens of thousands of lines. The 59k figure is a ceiling
for a full equivalent, not a promise that a smaller implementation is easy.

**Recommendation:** keep `quinn`, `h3`, and `h3-quinn`. If the dependency count
must fall by 18, the cheaper and more honest option is to drop HTTP/3, not to
reimplement it. Feature-gating is a measurement artifact, not a removal.

## 2. What Kunato uses

The HTTP/3 listener is server-side only. `src/proxy/http3.rs` uses:

- `quinn::Endpoint`, `ServerConfig`, `TransportConfig`, `QuicServerConfig`, and
  the rustls crypto adapter;
- `max_concurrent_bidi_streams`, the idle timeout, endpoint accept/refuse,
  graceful close, and `wait_idle`;
- `h3::server::builder`, `max_field_section_size`, connection accept, request
  resolver, request stream split;
- streaming request-body reads with `recv_data` / `poll_recv_data`;
- response head, streaming data, trailers, `finish`, `stop_stream`, and
  connection shutdown.

Kunato does not use an HTTP/3 client, server push, WebTransport, HTTP/3
datagrams, or extended CONNECT. That reduces the surface slightly, but the
remaining transport is still the hard part: packet protection, loss recovery,
congestion control, flow control, connection IDs, timers, and stream state.

## 3. Measured dependency impact

Removing the direct edges from `kunato` to the three crates in the current
default-feature graph removes 18 names (measured 2026-10-24):

```text
chacha20, cpufeatures, fastrand, futures, futures-executor, futures-io,
futures-macro, h3, h3-quinn, lru-slab, quinn, quinn-proto, quinn-udp, rand,
rand_core, rand_pcg, rustc-hash, tinyvec
```

The split:

| Removed layer | Names | Crates | Approximate `src/` lines |
| --- | ---: | --- | ---: |
| HTTP/3 (`h3`, `h3-quinn`) | 7 | `h3`, `h3-quinn`, `fastrand`, `futures`, `futures-executor`, `futures-io`, `futures-macro` | 20,100 |
| QUIC (`quinn` and its support crates) | 11 | `quinn`, `quinn-proto`, `quinn-udp`, `rustc-hash`, `lru-slab`, `rand`, `rand_core`, `rand_pcg`, `chacha20`, `cpufeatures`, `tinyvec` | 39,200 |
| **Total** | **18** | | **59,300** |

An earlier TODO measurement said 16. It missed `futures-io` and
`futures-macro`, which are removed only when feature unification is recalculated
without `h3` and `h3-quinn`.

The counts come from the crates' `src/` trees at the versions in `Cargo.lock`
(`quinn 0.11.12`, `quinn-proto 0.11.19`, `quinn-udp 0.5.16`, `h3 0.0.8`,
`h3-quinn 0.0.10`). They include inline tests and comments, so they are an
order-of-magnitude measure, not a precise estimate of production code.

Crates such as `futures-util`, `slab`, `tokio-util`, `socket2`, `once_cell`,
and `tracing` stay in the tree through `hyper-util`, `h2`, `rustls`, or other
dependencies and are not counted above.

### 3.1 Partial replacement is worse value

- **In-house HTTP/3 on quinn** removes 7 names for about 20,000 lines. It still
  requires QPACK, control streams, settings, request/response framing, trailers,
  GOAWAY, and error mapping, plus an adapter to quinn's streams.
- **In-house QUIC with HTTP/3** removes 11 names for about 39,000 lines. It
  requires the full transport, loss recovery, congestion control, and UDP I/O;
  the HTTP/3 layer would still need an adapter or an in-house implementation.
- **In-house quinn while keeping h3-quinn** is not possible: `h3-quinn` depends
  on `quinn` and exposes its types. Replacing quinn means replacing the adapter
  as well.

Neither partial path has a defensible KPI-per-effort ratio.

## 4. Implementation surface

### 4.1 QUIC transport

A credible server-side QUIC implementation would need at least:

- RFC 9000: packet formats, variable-length integers, frames, streams, flow
  control, connection IDs, path validation, connection close;
- RFC 9001: TLS 1.3 integration through rustls, initial/0-RTT/handshake/1-RTT
  key derivation, packet protection, header protection, key update;
- RFC 9002: loss detection, RTT estimation, congestion control (NewReno or
  CUBIC), pacing;
- anti-amplification limits, Retry and NEW_TOKEN, stateless reset, version
  negotiation, idle timeout, and timers;
- UDP socket handling, GSO/GRO if performance matters, MTU discovery, and ECN;
- connection migration and NAT rebinding behavior that browsers expect;
- bounded per-connection and global state under attack.

This is the same class of code as a TLS library or a TCP stack: a mistake is a
remote crash, a memory exhaustion, or an amplification vector, not a cosmetic
bug.

### 4.2 HTTP/3 and QPACK

- RFC 9114: control streams, settings, request and response streams, frame
  parsing, trailers, GOAWAY, stream errors, and connection errors;
- RFC 9204: QPACK static and dynamic tables, encoder/decoder, blocked streams,
  and header-size limits;
- the request/response lifecycle and graceful shutdown that the current adapter
  gets from `h3`;
- interoperability with browsers, `curl`, and HTTP/3 test tools.

Even without push, datagrams, and WebTransport, this is a substantial protocol
implementation.

## 5. Risk

| Risk | Why it matters |
| --- | --- |
| Security | The HTTP/3 listener is internet-facing UDP. Parser, frame, flow-control, and state-machine bugs can crash the process, exhaust memory, or amplify traffic. |
| Interoperability | Browsers exercise loss, reordering, MTU changes, NAT rebinding, key updates, and connection migration. A stack that works on loopback is not evidence of interop. |
| Testing | The project has HTTP/3 integration tests but no network simulator or interop matrix. A new stack needs loss/reorder/fuzz/interop infrastructure before it can be trusted. |
| Maintenance | QUIC and HTTP/3 are evolving. RFC errata, browser behavior, congestion-control tuning, and security advisories are ongoing work. |
| Opportunity cost | The same effort would deliver Phase 3a and several other product features; the dependency program's whole remaining backlog is smaller. |
| First-party risk | The dependency program reduces supply-chain surface, but this item moves risk from maintained, widely deployed crates into a new first-party network stack. For a WAF, that is the wrong trade. |

Kunato's design invariants include bounded resources, no panics on request
paths, and graceful degradation. Meeting them for a new QUIC stack would require
a long hardening period; the current `quinn`/`h3` stack already meets them.

## 6. Alternatives

| Option | KPI | Effort | Product effect | Verdict |
| --- | ---: | --- | --- | --- |
| Keep `quinn`/`h3`/`h3-quinn` | 0 | none | HTTP/3 stays | **Recommended** |
| Drop HTTP/3 | -18 | M | HTTP/3 removed | Cheapest path to -18; previously rejected by product decision |
| In-house QUIC + HTTP/3 | -18 | XXL | HTTP/3 stays | Not recommended; ~59k lines and a new security-critical stack |
| In-house HTTP/3 on quinn | -7 | L/XL | HTTP/3 stays | Poor ratio; ~20k lines |
| In-house QUIC only | -11 | XXL | HTTP/3 stays | Poor ratio; ~39k lines; adapter replacement required |
| Feature-gate HTTP/3 (default off) | -18 measured | S/M | HTTP/3 only in feature builds | Measurement artifact; `deny.toml` audits all features and the edge remains |
| Replace with another QUIC crate | 0 | M | HTTP/3 stays | No KPI gain; new supply chain |

### 6.1 Feature-gating caveat

Making `h3`, `h3-quinn`, and `quinn` optional behind a non-default `http3`
feature would lower the default-feature KPI by 18, but it would not remove the
dependency edge from the repository. `deny.toml` sets `[graph] all-features =
true`, so the crates are still audited. The release workflow would also need a
decision: publish a feature-enabled HTTP/3 binary (the measured KPI then
describes a build that is not shipped) or stop shipping HTTP/3 (a product
regression). The KPI section in `TODO.md` explicitly says feature-gating alone
does not reduce the monitored set. This option may be useful for binary size or
attack-surface reasons, but it should not be recorded as dependency removal.

### 6.2 When to revisit

- The product decision changes and HTTP/3 can be dropped. Dropping is cheaper
  than reimplementing.
- A maintained, smaller, permissively licensed QUIC implementation replaces
  `quinn` with fewer transitive crates. That is a dependency replacement, not
  an in-house implementation; it needs its own supply-chain review.
- A concrete requirement appears that `quinn` cannot express (for example, a
  custom congestion controller or transport extension). Even then, upstreaming
  to `quinn` is preferable to owning a stack.
- A serious unpatched vulnerability appears in `quinn` or `h3` and the
  maintainers cannot respond. That is a contingency, not a planned direction.

## 7. If the project still wants a spike

A time-boxed spike can validate the estimate without committing to the
implementation:

1. **Phase 0 (handshake).** Use rustls' QUIC API to accept one connection on
   loopback, complete the handshake, send a single `200` response, and close.
   Measure the lines required and the number of protocol edge cases that are
   not handled.
2. **Phase 1 (transport).** Add loss recovery, congestion control, flow control,
   and interop with `curl --http3`; fuzz the packet parser.
3. **Phase 2 (HTTP/3).** Add control streams, QPACK, request/response framing,
   trailers, and browser interop; run the security review.

Kill criteria for Phase 0: if the handshake already needs more than a few
thousand lines, if `curl` cannot complete a request, or if the design needs
`unsafe` or unbounded buffers, stop. A handshake-only spike does not reduce the
production risk of the full stack; it only confirms the cost estimate.

## 8. Recommendation

Do not implement HTTP/3 in-house. Keep `quinn`, `h3`, and `h3-quinn`.

The 18-name saving is real but small relative to the cost: the stack is nearly
twice the size of Kunato's entire source tree, and it is one of the most
security-sensitive dependencies in the project. The dependency program's
criterion is KPI impact divided by effort and risk; this candidate has the worst
ratio in the backlog. If the KPI target is the priority, revisit dropping HTTP/3
rather than rebuilding it.
