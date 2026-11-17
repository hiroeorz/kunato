# Monitoring console: remaining work

Date: 2026-11-16

Status: Tracking document for the work not covered by the implemented
[Phase 1](monitoring-console-phase1.md) through
[Phase 6](monitoring-console-phase6.md) layers. It records scope and sequence,
not a release commitment. The fictional browser prototype is retained as a
design reference; the delivered UI is the read-only page served by the console
binary.

Related: [console design](monitoring-console.md),
[product requirements](monitoring-console-requirements.md),
[storage and retention](monitoring-console-storage.md), and
[update-cadence evaluation](monitoring-console-cadence.md).

## 1. What is implemented

| Layer | State |
| --- | --- |
| WAF measurements | Atomic counters, process generation, ten-minute source ring, bounded supplementary dimensions, selected detail |
| Source API | Loopback `GET /console/snapshot` (version 3, version 2 input accepted) on the admin listener |
| Collection | `src/console/collector.rs`: one-second polling, coalescing, persistence admission, bounded memory, health |
| Storage | SQLite schema version 4, atomic writes/checkpoints, replay, capacity budget, private paths |
| History | UTC minute input, 1/5/10/20/60-minute materialization, 22 primary rejection reasons, 30-day logical expiry |
| Reads | Bounded `HistoryReader`, `Store::history`, `Store::correlations` |
| Correlation | Compact decoy evidence with 30-day/4,096-record bounds |
| Console runtime | `kunato console`: collector loop, health publication, bounded shutdown, independent process |
| Web delivery | Read-only HTTP API, bounded SSE, embedded real-data UI |
| Remote access | CIDR allowlist, Host validation, token login with server-side sessions, TLS, fail-closed validation |
| Packaging | `kunato-console.service`, installer enablement, and the multi-unit hardening check |
| Tests | Config, auth, allowlist, Host, TLS, history, SSE, runtime, and slow-consumer behavior |

## 2. Remaining items

Priority is the recommended order, not a dependency claim. Each item names the
authority (requirement or design clause) that defines acceptance.

### 2.1 Packaging and operations

| ID | Item | Authority |
| --- | --- | --- |
| OP-02 | Schema upgrade path beyond version 4 and a supported online backup procedure | design 8; storage 8 |
| OP-03 | Writer failure retry/backoff and priority shedding | phase 1; storage 2.2 |
| OP-04 | Capacity-pressure degradation (expire, shorten detail, coarsen, restrict) with measured thresholds | storage 7 |
| OP-05 | Production tuning of queue/query/maintenance/event/correlation budgets | design 8 |
| OP-06 | Integrated performance and failure validation (SSE latency, slow consumers, database stalls, multiple browsers) | cadence "Remaining validation" |

OP-01 is implemented: the release archive ships `kunato-console.service`,
`scripts/install.sh` installs it, and `scripts/check-unit-hardening.sh` checks
both units. The console stays off by default: `kunato init` and
`rules.example.yaml` ship the block commented out and the installer leaves the
unit disabled, so it runs only after both are explicitly enabled.

### 2.2 Measurements and presentation gaps

| ID | Item | Authority |
| --- | --- | --- |
| M-01 | Complete journal ingestion (selected snapshot events only today) | storage 2; phase 2 |
| M-02 | Full-body delivery duration (latency ends at response headers today) | phase 4 |
| M-03 | p50/p95/p99 presentation from the stored histograms | MET-07 |
| M-04 | Comparison periods and custom ranges in the real UI | MET-01 |
| M-05 | CSV export and historical event drill-down; the live list is snapshot-only | MET-10, LIVE-04 |
| M-06 | Honest labeling of estimates, omissions, gaps, and unavailable fields in every view | UI-02, UI-09, COUNT-11 |
| M-07 | Site dimension completeness beyond the `allowed_hosts` policy | phase 4 |
| M-08 | Arrival effects and event-age backgrounds in the delivered UI (prototype-only today) | LIVE-09, LIVE-10 |
| M-09 | Scroll-position preservation and pause/resume in the delivered UI (prototype-only today) | LIVE-06, LIVE-07 |

### 2.3 Open design decisions

| ID | Decision | Authority |
| --- | --- | --- |
| D-02 | Session recovery and credential rotation without a restart | design 8 |
| D-03 | Certificate names, service permissions, and behavior when the console runs as a different account than the WAF | design 8 |
| D-04 | Event cursor/replay behavior and pause/resume bounds | design 8; LIVE-06 |
| D-05 | Future schema versions and backup workflow | design 8 |
| D-06 | Final storage/query/maintenance limits | design 8 |
| D-07 | Language-localization policy for the UI | requirements 1 |

Resolved by Phase 5/6: the console subcommand and configuration section, the
loopback/remote listener policy, token authentication with server-side
sessions, and PEM or combined ACME-bundle certificate delivery with reload on
change.

Resolved by packaging: the console enablement workflow. The console is off by
default, `kunato init` and `rules.example.yaml` ship the block commented out,
and the installer installs `kunato-console.service` without enabling it.

### 2.4 Documentation debt

| ID | Item |
| --- | --- |
| DOC-01 | Keep [development.md](development.md) in sync with every new `console` field and command |
| DOC-02 | Update the console status tables when a phase is implemented |
| DOC-03 | Retire superseded prototype periods (90 days, one year) and the JST default when the real UI replaces it |
| DOC-04 | Promote the minimal delivered UI to the full interaction design (arrival effects, age backgrounds, pause, scroll preservation) |

## 3. Sequence

1. Service account and certificate permission decision for a separate console
   account.
2. Measurement gaps and the remaining interaction design in the delivered UI.
3. Capacity, backup, and production tuning work.

No remaining item changes rule evaluation, protective verdicts, the managed rule
format, decoy enforcement, or WAF forwarding. A console failure remains an
observation failure.
