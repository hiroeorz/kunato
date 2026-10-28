# Kunato

[![CI](https://github.com/hiroeorz/kunato/actions/workflows/ci.yml/badge.svg)](https://github.com/hiroeorz/kunato/actions/workflows/ci.yml)

Kunato is a lightweight Web Application Firewall (WAF) written in Rust, built for personal users who want an easy-to-deploy protection layer in front of their web applications.

![Kunato-chan, the project mascot: a chibi character holding a shield marked with an X](./kunato-chan.png)

It runs as a reverse proxy between clients (browsers, apps) and your HTTP server,
inspects incoming requests against categorized, YAML-defined rules, and applies one
of three actions: **BLOCK**, **ALLOW**, or **LOG**.

> **Status:** Early development. The configuration format and public interfaces are
> not yet stable and may change without notice.

## Features

- **Reverse proxy** — Sits between browsers/apps and your HTTP server, forwarding
  traffic while inspecting every request.
- **Host allowlist** — Rejects requests whose Host or `:authority` is missing,
  malformed, or not in `allowed_hosts` with `400`/`421` before rules run. The
  installer seeds the list from `--acme-domain`; add other names or IPs with
  `--allowed-host`.
- **HTTP/2, HTTP/3, and HTTP/1.1** — Accepts HTTP/2 over TLS (ALPN) and
  cleartext h2c (prior knowledge), plus optional HTTP/3 over QUIC, falling back
  to HTTP/1.1 automatically. Upstream requests are sent over HTTP/1.1.
- **Automatic TLS certificates** — Obtains and renews Let's Encrypt
  certificates directly over the ACME protocol (TLS-ALPN-01 on the HTTPS
  port). No external tools such as certbot, no cron job, and no deploy hooks:
  list your domains under `tls.acme` and Kunato handles issuance, renewal, and
  in-place rotation, caching the certificate locally between restarts.
- **WebSocket proxying** — Forwards HTTP/1.1 upgrade handshakes to the upstream
  and tunnels the connection both ways. The handshake passes through the rule
  engine and protection budgets; idle tunnels are closed automatically.
- **Categorized rule sets** — Rules are grouped into named categories (for example
  `sql-injection` or `xss`). Each category defines a default action, and individual
  rules can override it.
- **Daily CVE-driven rule updates** — An optional updater automatically refreshes
  the managed rule set once a day with signatures for the latest exploited CVEs,
  using conditional requests, SHA256 verification, and full validation before an
  atomic swap.
- **Response header rewriting** — Removes or replaces identifying response headers
  such as `Server` and `X-Powered-By` on upstream responses and Kunato's own
  block/error responses alike.
- **Response inspection** — Response-phase categories match upstream responses on
  status, headers, and body (up to a size limit) and can block, log, or pass them
  through. The remainder of oversized responses is streamed uninspected.
- **Encoded body inspection** — Bodies compressed with gzip, deflate, brotli, or
  zstd are decompressed for matching, and request bodies are additionally decoded
  by content type (`application/x-www-form-urlencoded` and JSON escapes).
  Forwarded traffic is never modified.
- **Upload content inspection** — Multipart file parts are checked against their
  declared type and filename extension; executable, script, or markup content
  behind an image, PDF, office, media, or font claim is rejected before rules run.
  `strict` mode also covers generic binary claims.
- **YAML rules with hot reload** — Rules are written in YAML. Changes to the rule
  file are detected at runtime and reloaded on the fly without restarting the
  process or dropping connections.
- **High fault tolerance** — Keeps serving with the last known good configuration,
  isolates failures, and avoids disrupting traffic during reloads.
- **Guided install** — One `curl | sudo sh` command installs the static binary,
  the systemd service, the configuration, and the initial rule set on a Linux
  server.
- **Behavioral abuse detection** — Per-source windows over upstream responses
  flag iterative `404` probing and authentication-failure bursts, and a global
  window records distributed authentication failures. The example configuration
  blocks enumeration and leaves authentication signals in observation mode;
  `BLOCK` remains configurable per signal.
- **Trusted proxy support** — Explicit proxy IP/CIDR trust resolves client
  identities behind CDNs and load balancers for rules, request limits, and
  behavioral bans. See the [deployment checklist](docs/behavioral-readiness.md).
- **DoS / DDoS detection and mitigation** — Detects abnormal request patterns and
  automatically throttles or blocks abusive sources.
- **Simple deployment** — One binary and one YAML configuration file. No database,
  no external services, no complex setup.
- **Rust implementation** — Memory safety and predictable performance in a single
  static binary with no runtime dependencies.

![Kunato overview: client requests pass through the inspection engine, malicious traffic such as SQL injection, XSS, path traversal, and DDoS is blocked, allowed requests are forwarded to the upstream server, and rules are refreshed daily from CVE data](./KunatoFlow.png)

## How It Works

```
                 inspect & apply rules
Client ──────►  ┌───────────────────┐  ──────►  Upstream HTTP server
(browser/app)   │  Kunato (WAF)     │
                │  reverse proxy    │  ◄──────  (response)
                └───────────────────┘
```

1. A request arrives at Kunato.
2. If `allowed_hosts` is configured, the Host / `:authority` is checked first;
   a missing, malformed, or unlisted name is rejected with `400`/`421`.
3. Categories are evaluated in the order they appear in the configuration, and
   rules within each category in their order.
4. The first rule whose conditions all match is handled according to its effective
   action:
   - `ALLOW` — forwards the request and stops evaluation.
   - `BLOCK` — rejects the request immediately (default: `403 Forbidden`).
   - `LOG` — records the match and continues evaluation.
5. If no rule matches, the request is forwarded to the upstream (pass-through).
6. Response-phase categories run on the upstream response the same way. `BLOCK`
   replaces the upstream response with the configured response; `ALLOW` stops
   response evaluation and passes the response through unchanged.

## Getting Started

Kunato ships as a single static binary for Linux. On a server with systemd, one
command installs the binary, the service, the configuration, and the initial
rule set, and terminates TLS with an automatically obtained Let's Encrypt
certificate:

```sh
curl -fsSL https://raw.githubusercontent.com/hiroeorz/kunato/main/scripts/install.sh \
  | sudo sh -s -- \
      --upstream http://127.0.0.1:8080 \
      --acme-domain example.com \
      --acme-contact admin@example.com \
      --yes
```

Replace the upstream with the web server Kunato protects, and the domain and
contact with a DNS name that resolves to this server and an address for
Let's Encrypt expiry notices. Automatic certificates need TCP port 443
reachable from the internet, so wildcards and setups behind a TLS-terminating
CDN or proxy must manage certificates manually (see
[Deployment](docs/development.md#deployment) for the full option list).

The `--acme-domain` names are also written to `allowed_hosts`, so requests with
any other Host header are rejected with `421`. If clients reach Kunato through
another name or an IP address (for example a health check), add it with
`--allowed-host` or edit `/etc/kunato/kunato.yaml` (see
[Host allowlist](docs/development.md#host-allowlist)).

Upgrading an installed server (Kunato v0.3.2 and later) uses the built-in
command, which reruns the installer published with the target release:

```sh
sudo kunato upgrade                    # upgrade to the latest release
sudo kunato upgrade --version v0.4.0   # pin a specific release
sudo kunato upgrade --dry-run          # print what would run
```

Existing configurations are kept as-is, including an absent `allowed_hosts`;
add the field to the existing file to enable host checking.

The service starts automatically; the first start orders the certificate in
the background, so allow a few seconds before TLS works. Confirm it is
running, then edit `/etc/kunato/kunato.yaml`; changes are applied without a
restart:

```sh
systemctl status kunato
sudo kunato log -n 50
kunato metrics                       # metric table from :9090
sudo kunato validate
```

`kunato metrics` prints one row per metric in a bordered table with the name and
value columns, leaving out the Prometheus `# HELP` and `# TYPE` lines, aligning
values to the right, and adding the local date and time to timestamp gauges;
pass `--listen <ADDR>` when the admin listener uses another loopback address.

`kunato log` reads the same systemd journal and adds structured filters:

```sh
sudo kunato log -f                                  # new entries, real time
sudo kunato log --ip 203.0.113.9 --since '1 hour ago'
sudo kunato log --attack sqli --action BLOCK
sudo kunato log --status 429 --format table         # aggregated 429 events
sudo kunato log --attack cve-2025 --format json | jq .
```

`--attack` accepts the category-based classes listed by
`kunato log --list-attacks`; `--category` and `--rule` select exact names.
Rate-limit and ban rejections are aggregated per source with a `suppressed`
count (a new ban is emitted immediately), so `--ip` remains usable during a
flood without writing one journal line per rejected request.

Rerunning the installer upgrades the binary and unit, keeps the
configuration, and restarts the service; `--uninstall` removes them. See
[Managed Rules and Automatic Updates](#managed-rules-and-automatic-updates) for
what is refreshed after installation, and
[Deployment](docs/development.md#deployment) for installer details and building
from source.

## Managed Rules and Automatic Updates

The installer enables `rules_update`, so the rule set stays current without
manual work. Every `interval` (default `24h`, randomized by `jitter_percent`,
default 10%) Kunato:

1. sends a conditional request (`If-None-Match` / `If-Modified-Since`) and stops
   immediately on `304 Not Modified`;
2. downloads the rule file and verifies its SHA256 digest against `checksum_url`;
3. parses and fully validates it — regex compilation, ReDoS guards, action
   resolution, size limits — before replacing anything;
4. swaps the file in atomically, and the configuration watcher hot-reloads it.

Any failure (network, checksum mismatch, invalid rules, size limit) leaves the
current rules active; failures are logged and counted in the
`kunato_rules_update_*` metrics, and a rule set that needs a newer build is
counted separately in `kunato_rules_update_incompatible_total` (see
[Rule set format compatibility](docs/development.md#rule-set-format-compatibility)).
The full field reference lives in
[Rule sources and updates](docs/development.md#rule-sources-and-updates).

Updates run automatically, so a manual check is normally unnecessary. To apply
the latest rule set immediately instead of waiting for the next interval, run:

```sh
sudo kunato update-rules
```

This performs a single check and exits, and is the same command the installer
uses for the first download.

Local changes are never overwritten: exemptions and rule disables belong in
`overrides_file` (`/etc/kunato/overrides.yaml` when configured), which is
evaluated before the managed set. The updater writes exactly one file — the
managed rules file — and nothing else.

### Installed files and directories

```text
/
├── usr/
│   └── local/
│       └── bin/
│           └── kunato                         # binary (0755 root:root)
├── etc/
│   ├── systemd/
│   │   └── system/
│   │       ├── kunato.service                 # unit (0644)
│   │       └── multi-user.target.wants/
│   │           └── kunato.service -> ../kunato.service
│   └── kunato/                                # settings (0750 root:kunato)
│       ├── kunato.yaml                        # main configuration (0640 root:kunato)
│       ├── overrides.yaml                     # only when configured (0640 root:kunato)
│       └── tls/                               # only with --tls-cert/--tls-key (0750 root:kunato)
│           ├── cert.pem                       # (0640 root:kunato)
│           └── key.pem                        # (0640 root:kunato)
└── var/
    └── lib/
        └── kunato/                            # StateDirectory (0750 kunato:kunato)
            ├── rules.yaml                     # managed rule set (auto-updated)
            └── rules.yaml.update-state        # updater bookkeeping (auto-updated)
```

Auto-updated: `/var/lib/kunato/rules.yaml` and its `rules.yaml.update-state`
sidecar (last success timestamp, HTTP validators). Never touched by the updater:
everything under `/etc/kunato/`. The service runs as the `kunato` user (created
by the installer, no home directory) and only needs write access to
`/var/lib/kunato/`.

## Attack Coverage

[Attack coverage](docs/attack-coverage.md) tracks which attack classes the
bundled rules and engine mechanisms cover, which are partial, and which are
gaps, with the evidence behind every verdict. It is refreshed whenever the rule
set or the engine changes.

## Security Lab

The local security lab starts a real recording HTTP server and Kunato in
isolated Docker containers, with no published ports or host networking, and
exercises them in a sandbox with the same pinned tools used for real scanning:
goTestWAF, sqlmap, Nuclei against an Apache 2.4.49 CVE-2021-41773 fixture, ffuf,
ZAP, and k6, plus common-injection/API and recent CVE/AI surface cases, raw
HTTP/1.1 framing, HTTP/2 preface, and WebSocket cases.
Every case is sent directly to the origin first, without Kunato, so the test is
valid before the protected result is trusted; each run retains origin receipts,
Kunato logs, resource measurements, and recovery evidence. See
[how the lab tests sandbox suites](docs/security-lab-testing-model.md) for the
topology, control/evidence model, verdicts, and diagrams.

Run the full sandbox suite, or one focused suite at a time:

```sh
scripts/security-lab.sh prepare
scripts/security-lab.sh run --sandbox-suite all
scripts/security-lab.sh run --sandbox-suite common
scripts/security-lab.sh run --sandbox-suite recent
scripts/security-lab.sh run --sandbox-suite response
scripts/security-lab.sh run --sandbox-suite graphql
scripts/security-lab.sh run --sandbox-suite jwt
scripts/security-lab.sh run --sandbox-suite hardening
scripts/security-lab.sh run --sandbox-suite ssrf-xxe
scripts/security-lab.sh run --sandbox-suite credential-stuffing
scripts/security-lab.sh run --sandbox-suite global-auth
scripts/security-lab.sh run --sandbox-suite scraping
scripts/security-lab.sh run --sandbox-suite protocol
scripts/security-lab.sh run --sandbox-suite slow
scripts/security-lab.sh run --sandbox-suite load
```

## Development

Running from source, the black-box test suite, deployment and building from
source, the full configuration reference, DoS / DDoS protection, and
contributing notes live in the
[development guide](docs/development.md).

## License

Kunato is provided "as is", without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability, whether
in an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or the use or other dealings in the software. You
use it at your own risk, and you remain responsible for keeping your applications
updated and securely configured.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
