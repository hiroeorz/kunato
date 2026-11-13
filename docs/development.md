# Kunato development guide

Everything beyond the quick start in the [README](../README.md): running Kunato
from source, the black-box test suite, deployment and building from source, the
full configuration reference, DoS / DDoS protection, fault tolerance, the
roadmap, and contributing notes.

## Trying It Locally

Running from source requires Rust 1.89 or later (edition 2024). The repository
includes a small example upstream that logs every request to stdout:

```sh
cargo run --example upstream -- --listen 127.0.0.1:3000
cargo run -- --config rules.example.yaml
```

Open `http://127.0.0.1:8080/` in a browser or use `curl -v`. The response reports
the method, target, headers, and body as seen by the upstream, including the
`X-Forwarded-*` headers Kunato adds. The bundled `trusted-sources` category is
disabled by default, so block rules apply to local requests; enable it and narrow
its ranges only when you deliberately want a trusted bypass.

## Black-Box Testing

Run the whole test with one command: it builds the binaries, starts the example
upstream and Kunato with a test configuration that does not trust the client,
replays both request lists, and prints a colored report with allow/block
pass and fail counts plus per-phase latency (min/avg/max):

```sh
./scripts/blackbox-test.sh
```

The report exits non-zero when an allowed request is not forwarded, a blocked
request reaches the upstream, or the upstream access count does not match.
`--skip-build`, `--parallelism N`, `--color auto|always|never`, and
`--workdir DIR` adjust the run; the log and test-config paths are printed at
the end.

`blackbox/` itself is a dependency-free driver that replays request lists in
parallel and prints the response status of each request:

```sh
cargo run --release --manifest-path blackbox/Cargo.toml -- \
  --blocked blackbox/requests/blocked.txt \
  --allowed blackbox/requests/allowed.txt \
  --addr 127.0.0.1:8080 \
  --parallelism 5
```

The request-list format supports HTTP/2 cleartext probes with `proto=h2c`,
including HPACK compression bombs (`hpack_bomb=N`) and oversized header blocks
(`pad_header=N`); see `--help` and the header of `blocked.txt`.

`--parallelism` defaults to 5. The two lists are split by expectation; correctness
is judged from the logs: the upstream access log should contain only the allowed
requests, and the Kunato log should show the blocked requests as blocked. Run it
against a configuration that does not trust the test client. If you enable
`trusted-sources`, exclude the driver's source address first. If the configuration has strict protection
limits, start Kunato with `--disable-protection` so rate limits and bans do not
interfere with the driver.

`blocked.txt` doubles as a CVE regression corpus. CVE coverage targets
vulnerabilities with a CVSS base score of 7.0 or higher, and only attacks that
can be expressed as an HTTP request are listed. Classes that need TLS-internal
state, raw connection framing, or a malicious upstream are recorded as comments
at the end of the list instead.

For the selected attack tools, isolated local lab topology, evidence requirements,
and the discovery-to-regression process, see the
[local adversarial testing design](security-testing.md). The recording origin,
goTestWAF, DVWA/sqlmap, one CVE/Nuclei sandbox suite, ffuf path discovery and
enumeration behavior, the authenticated ZAP spider/passive baseline, and 25
deterministic mutation variants with an optional OWASP CRS comparison are
available through the [lab entrypoint](../lab/README.md). ZAP active scanning
remains out of the passing plan; the protocol/WebSocket, slow-HTTP, and k6 mixed
load sandbox suites are implemented.

## Dependency Audit

`cargo deny check` runs the advisory, license, ban, and source policy in
`deny.toml`. On a machine with a writable `$CARGO_HOME` this is sufficient. In a
read-only sandbox, or when the glibc/musl target pair makes cargo-deny resolve
platform-specific dependencies outside the cached set, run the wrapper instead:

```sh
./scripts/check-deny.sh
```

cargo-deny only passes `--filter-platform` to `cargo metadata` when exactly one
target is configured; with two targets it resolves every platform's
dependencies, including Android-only crates. The wrapper checks each target
from `deny.toml` separately and points the advisory database at a temporary
writable copy, so it does not need to write to `$CARGO_HOME`. It uses the cached
advisory database when present and fetches it otherwise.

## Deployment

The installer used in [Getting Started](../README.md#getting-started) downloads
the release for your architecture, verifies its SHA256 checksum, installs the
binary to `/usr/local/bin/kunato` and the systemd unit, writes
`/etc/kunato/kunato.yaml`, fetches the managed rule set, validates the
configuration, and enables the service. Key options:

| Option                    | Description                                                              |
| ------------------------- | ------------------------------------------------------------------------ |
| `--version TAG`           | Install a specific release (default: the latest).                        |
| `--upstream URL`          | Upstream server the WAF forwards to; required on first install.          |
| `--listen ADDR`           | Listen address (default `0.0.0.0:443`).                                   |
| `--tls-cert`/`--tls-key`  | PEM certificate chain and key; copied to `/etc/kunato/tls/`.             |
| `--acme-domain DOMAIN`    | Obtain Let's Encrypt certificates automatically; repeatable.             |
| `--acme-contact EMAIL`    | Contact email registered with the ACME account.                          |
| `--acme-staging`          | Use the Let's Encrypt staging directory (for testing).                   |
| `--allowed-host HOST`     | Add a Host name or IP literal to `allowed_hosts`; repeatable.            |
| `--rules-url URL`         | Managed rule set URL (see Managed Rules and Automatic Updates).          |
| `--no-start`              | Install and validate without enabling or starting the service.            |
| `--no-banner`             | Do not print the banner after a successful install.                       |
| `--allow-empty-rules`     | Start even when the initial rules download fails (blocks nothing).        |
| `--yes`                   | Never prompt; fail instead of asking.                                    |
| `--uninstall`             | Stop and remove the service and binary.                                  |
| `--purge`                 | With `--uninstall`, also remove `/etc/kunato` and `/var/lib/kunato`.      |

TLS material passed with `--tls-cert`/`--tls-key` is copied to `/etc/kunato/tls/`
so the service user can read it. Re-copy it and restart the service when the
certificate is renewed; as a certbot deploy hook
(`/etc/letsencrypt/renewal-hooks/deploy/kunato`):

```sh
#!/bin/sh
install -m 0640 -o root -g kunato /etc/letsencrypt/live/example.com/fullchain.pem /etc/kunato/tls/cert.pem
install -m 0640 -o root -g kunato /etc/letsencrypt/live/example.com/privkey.pem /etc/kunato/tls/key.pem
systemctl restart kunato
```

Instead of passing certificate files, pass one or more `--acme-domain
example.com` flags. Kunato then obtains the certificate itself and renews it
without a deploy hook or restart; see
[Automatic certificates](#automatic-certificates-lets-encrypt).

`kunato init` also writes those domains to `allowed_hosts` (the installer
passes them through), so a new install rejects requests with another Host
header with `421`. Add any other name or IP clients use with `--allowed-host
NAME`; installs that manage certificates manually can opt in the same way (see
[Host allowlist](#host-allowlist)).

Running the installer again upgrades the binary and unit while keeping the
existing configuration.

New starter configurations also enable experimental decoys with `on_reuse:
BLOCK`. The site origin uses the first ACME domain or allowed host; a wildcard
host uses its `blog` subdomain. Without either input, edit the generated
`https://blog.example.com` example to your public HTTPS origin. Decoys do not
require `allowed_hosts`. See [Experimental decoys](#experimental-decoys).

A successful install or `kunato upgrade` prints the banner produced by
`kunato banner` when stdout is a terminal. `--no-banner` (or
`KUNATO_NO_BANNER`) skips it, and `NO_COLOR` keeps the banner but drops the
ANSI colors. Run `kunato banner` to print it again.

The installer downloads only over HTTPS (`curl --proto '=https' --proto-redir
'=https'`), validates the version tag, and extracts the archive with
`--no-same-owner --no-same-permissions` before installing files as root.
`KUNATO_BASE_URL` must therefore be an `https://` URL. `kunato upgrade` reruns
the installer published with the target release in a cleared environment (only
`PATH` is inherited, so a caller-supplied `KUNATO_BASE_URL` or a planted `curl`
cannot steer the root install). It trusts the GitHub release and tag, so
signing release assets and verifying them in the installer remains a separate
hardening task.

Without network access, or to build a custom binary, build from source (Rust
1.89 or later, edition 2024):

```sh
sudo apt-get install musl-tools   # Debian/Ubuntu; provides musl-gcc
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Install the binary to `/usr/local/bin/kunato`, generate a configuration with
`kunato init --upstream <url> --acme-domain example.com --output
/etc/kunato/kunato.yaml` (or `--tls-cert <pem> --tls-key <pem>` for a manually
managed certificate), download the first rules file with `kunato
update-rules`, and enable `packaging/kunato.service`. `rules.example.yaml` is a
practical starting point with rules for SQL/NoSQL injection, XSS, path traversal,
command injection, SSRF, XXE, malicious uploads, scanners, sensitive files, and
more. `scripts/release.sh X.Y.Z` cuts a release: it bumps the `version` in
`Cargo.toml`, commits and pushes it, and tags and pushes `vX.Y.Z`. The tag
builds and uploads static musl tarballs, checksums, and the installer through
GitHub Actions; `kunato --version` identifies the installed release because
the release workflow rejects a tag that does not match the package version.

## Configuration

Kunato is configured through a single YAML file. The file defines where Kunato
listens, which upstream server it forwards to, and a list of rule **categories**.
All commands read `/etc/kunato/kunato.yaml` by default; pass `--config PATH` to
use a different file (for example `rules.example.yaml` when running from source):

- `listen` — address and port to bind.
- `upstream` — base URL of the upstream HTTP server.
- `allowed_hosts` — optional Host/authority allowlist; omit to disable, and list
  every name and IP address clients use (see [Host allowlist](#host-allowlist)).
- `content_routes` — optional authoring routes whose request body is content
  rather than parameters; body-targeting rules are skipped there (see
  [Content routes](#content-routes)).
- `categories` — ordered list of rule categories.
- `rules_file` — optional categories-only file refreshed by the daily rules updater.
- `overrides_file` — optional categories-only file with local exceptions,
  evaluated before every other rule source.
- `rules_update` — daily refresh of `rules_file` (see
  [Managed Rules and Automatic Updates](../README.md#managed-rules-and-automatic-updates)).

`listen` accepts IPv4 and IPv6 socket addresses; quote IPv6 literals in YAML
(`listen: "[::]:443"`). On Linux, `[::]` is dual-stack and also serves IPv4
clients as IPv4-mapped addresses, even if the host has no routable IPv6 address;
use `0.0.0.0` where the kernel has IPv6 disabled or `net.ipv6.bindv6only=1`.

Configuration and rule files use a YAML subset: block and flow collections,
plain, single-quoted, double-quoted, and block scalars, comments, explicit `?`
mapping keys (block `? key` / `: value` or flow `{? key: value}`), and flow
pairs (`[key: value]`). The parser is in-tree (`src/yaml/`). Flow collections
and quoted scalars may span multiple lines; block scalars and multi-line plain
scalars are supported. Document markers (`---`, `...`) must be on their own
line. Anchors, aliases, merge keys, explicit tags, `%YAML`/`%TAG` directives,
multiple documents in one file, and complex mapping keys (collection keys) are
rejected with a parse error. Duplicate mapping keys are rejected too. Tabs are
allowed in quoted scalars and block scalar content, but are rejected for
indentation and inside plain scalars. Quoting is significant for untagged
values such as `status`, where `404` is a numeric code and `'404'` is a text
match. Typed fields accept quoted values, so `window: '60s'` and `window: 60s`
are equivalent.

Each category groups related rules (for example SQL injection or XSS signatures)
and defines a default action that its rules inherit. Individual rules can override
the category defaults.

Rules are written in a compact form: `name` on one line, followed by a flow-style
`match` mapping on the next. Rules that override category defaults add one line per
extra field (`action`, `enabled`, `description`, `response`), and larger match
mappings can fall back to block style. Both forms are plain YAML and can be mixed.

### Example

```yaml
listen: 0.0.0.0:8080
upstream: http://127.0.0.1:3000

categories:
  # Trusted clients: matching rules forward the request immediately and skip
  # all remaining categories.
  - name: trusted-sources
    enabled: false          # enable only for genuinely trusted source ranges
    action: ALLOW
    rules:
      - name: internal-networks
        match: { source_ip: [10.0.0.0/8, 192.168.0.0/16] }
      - name: uptime-monitor
        match: { source_ip: 203.0.113.10, path: ^/health$ }

  # SQL injection: the category default blocks matching requests.
  - name: sql-injection
    action: BLOCK
    response: { status: 403, body: Forbidden }
    rules:
      - name: union-select
        match: { regex: '(?i)\bunion\b.{0,40}\bselect\b', in: [query, body] }
      - name: comment-obfuscation
        match: { regex: '(?i)(/\*!|--\s|#\s)', in: [query, body] }
      - name: tuning-heuristics         # disabled while false positives are investigated
        enabled: false
        match: { regex: '(?i)\bor\s+1\s*=\s*1\b', in: [query, body] }
      - name: detection-only            # logs instead of blocking while tuning
        action: LOG
        match: { regex: '(?i)(sleep\s*\(|benchmark\s*\()', in: [query, body] }

  # Cross-site scripting: also blocks by default.
  - name: xss
    action: BLOCK
    rules:
      - name: script-tags
        match: { regex: '(?i)<\s*script\b', in: [query, body, headers] }
      - name: event-handlers
        match: { regex: '(?i)\bon(error|load|click|mouseover)\s*=', in: [query, body] }
      - name: javascript-uri
        match: { regex: '(?i)javascript\s*:', in: [query, body] }

  # Path traversal: blocks by default. Larger match mappings may use block style.
  - name: path-traversal
    action: BLOCK
    rules:
      - name: dot-dot-slash
        match:
          regex: ['\.\./', '(?i)%2e%2e%2f', '(?i)%2e%2e/']
          in: [path, query, body]
      - name: encoded-backslash
        match: { regex: '(?i)(%5c|\.\.\\)', in: [path] }

  # Scanners and sensitive endpoints: logged by default, but individual rules
  # override the category action and block.
  - name: scanners
    action: LOG
    rules:
      - name: scanner-user-agents
        match:
          headers:
            User-Agent: ['(?i)sqlmap', '(?i)nikto', '(?i)(nmap|masscan|zgrab)']
      - name: sensitive-files            # overrides the category default
        action: BLOCK
        match: { path: '(?i)(^|/)(\.env|\.git/|wp-admin|phpmyadmin)' }

  # Response inspection: runs on the upstream response after it arrives. The
  # default `in` target in a response category is `response_body`.
  - name: response-leaks
    phase: response
    action: LOG
    rules:
      - name: private-key-material
        action: BLOCK
        match: { regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----' }
      - name: versioned-server
        match: { response_headers: { Server: '(?i)(apache|nginx)/[0-9]' } }
      - name: upstream-error
        match: { status: 5xx }
```

### Evaluation

1. Request-phase categories (`phase: request`, the default) are evaluated in the
   order they appear in the file, and rules within a category in their order. A
   category with `enabled: false` is skipped entirely.
2. The first rule whose conditions all match wins. Its effective action and
   response are resolved with rule-level values taking precedence over
   category-level defaults.
3. The effective action is applied:
   - `ALLOW` — forwards the request and stops evaluation.
   - `BLOCK` — rejects the request with the effective response (default:
     `403 Forbidden`) and stops evaluation.
   - `LOG` — records the match and continues evaluation.
4. If no rule matches, the request is forwarded (pass-through).
5. After the upstream responds, response-phase categories (`phase: response`) run
   in document order. They match the upstream response plus the request context;
   `BLOCK` replaces the response with the effective response, `ALLOW` stops
   response evaluation and passes the response through unchanged, and `LOG`
   records the match and continues.

Every rule must resolve to an effective action: a rule without its own `action`
requires the category to define one. The configuration is rejected at load time
otherwise.

### Rule sources and updates

Rules can come from three places. Sources are concatenated in this order, and
evaluation starts with the first source, so earlier sources win:

1. `overrides_file` — a categories-only YAML document for local exceptions and
   tuning.
2. categories written directly in the configuration file.
3. `rules_file` — the managed rule set refreshed by `rules_update`.

```yaml
rules_file: /var/lib/kunato/rules.yaml
overrides_file: /etc/kunato/overrides.yaml
```

```yaml
# /etc/kunato/overrides.yaml
disabled_rules: [union-select]      # drop these rule names from every other source

categories:
  # Fix a false positive before the managed rules run: ALLOW wins over later BLOCKs.
  - name: local-exceptions
    action: ALLOW
    rules:
      - name: admin-search
        match: { path: ^/admin/search$, source_ip: 192.168.0.0/16 }
```

The external files are categories-only: `categories`, plus `disabled_rules` in
the overrides file (listing it in `rules_file` is rejected, so a downloaded file
can never weaken local overrides). Relative paths are resolved against the
directory of the configuration file. Missing files fail validation; a running
instance keeps its last known good rules if a reload fails.

`rules_update` keeps `rules_file` fresh without manual downloads:

```yaml
rules_update:
  enabled: true
  url: https://raw.githubusercontent.com/hiroeorz/kunato/main/dist/rules.yaml
  checksum_url: https://raw.githubusercontent.com/hiroeorz/kunato/main/dist/rules.yaml.sha256
  interval: 24h        # default
  jitter_percent: 10   # randomize the next check by ±10% (default 10, max 50)
  max_bytes: 1048576   # download size limit (default 1 MiB)
```

The URL must use https; plain http is accepted only for loopback hosts, which is
handy for tests and local mirrors. Redirects must satisfy the same policy for
the URL they started from: an https download only follows https, and a
loopback-http download only follows https or loopback http, so a redirect can
never downgrade the transport. Redirects may also leave the configured origin
at most twice, which keeps the release channel's CDN bounce-through working
while a chain that keeps moving the download to other hosts fails the update;
every cross-host hop is logged. Every `interval` the updater sends a
conditional request (`If-None-Match`/`If-Modified-Since`), downloads any new
file, verifies its SHA256 digest against `checksum_url`, validates it with the
full rule compiler (regex and ReDoS guards included) together with the inline
and overrides sources, replaces the file
atomically, and installs that already-compiled snapshot directly. The file
watcher shares the source timestamps of the applied snapshot, so one update
compiles the rule set once instead of once for validation, once for the reload,
and once more on the watcher's next tick. Any failure — network,
checksum mismatch, invalid rules, size limit — leaves the current rules
untouched and is reported in the logs and metrics. The updater state (last
success, next due time, HTTP validators) is stored next to the rules file.
`kunato update-rules` performs a single check and exits; the installer uses it
for the first download. The replacement file keeps the owner and mode of the
file it replaces (a fresh file is `0640` and owned by the state directory's
owner), so running `sudo kunato update-rules` does not leave a root-owned file
the service user cannot read.

The SHA256 digest guards against corrupted or truncated downloads; it is
fetched over the same TLS connection as the rules file, so it does not add
authenticity by itself. A detached minisign signature
(`<rules url>.minisig`) is verified against keys embedded in the binary when one
is configured (HTTPS rule URLs only; the loopback HTTP development path skips it
with a warning). The signed minisign trusted comment is verified together with
the file signature, and its timestamp must not move backwards, so replaying an
older rule set does not roll the install back. `kunato upgrade` verifies
`install.sh.minisig` before running the installer as root and refuses a release
tag older than the running binary unless `--allow-downgrade` is given. See [release-signing.md](release-signing.md) for key
generation, signing, rotation, and the remaining trust limits.

### Content routes

Authoring endpoints such as a CMS article editor submit authored content
(Markdown, HTML, code samples) in the request body. That content is
byte-for-byte indistinguishable from an attack: a Markdown code fence or an
inline code span such as ``` `curl | sudo sh` ``` is also a valid shell command
substitution, and any rule that excludes prose can be evaded by padding a real
payload the same way. Declare such endpoints as content routes instead of
adding per-article or per-notation exceptions:

```yaml
content_routes:
  - path: ^/admin/posts(?:/|$)
    methods: [POST, PUT, PATCH]
```

The body targets of every rule are skipped for a matching request, so a
body-only rule cannot match; a rule that targets both the body and the query
still matches on the query. Every other check stays active: `allowed_hosts`,
path, query, cookie, and header targets, the form guard, upload inspection,
GraphQL limits, DoS protection, and response-phase rules. A body that exceeds
`limits.max_body_bytes` is forwarded rather than rejected by the strict
body-inspection rule because there is no body rule to satisfy, but the form and
upload guards still apply.

`path` is a regular expression matched against every decoded and normalized
form of the request path. It must be anchored at the start with `^` so an
unanchored pattern cannot exempt a different subtree. The route applies only
when every form matches, so a
request cannot be normalized by the upstream into a different endpoint after
the body rules were skipped. `methods` is optional and defaults to every
method; names are the case-sensitive uppercase tokens used by rule matches, and
an explicitly empty list is rejected. Methods are matched on the wire, like rule
methods, so a Rails form update that sends `POST` with `_method=patch` needs
`POST`. Up to 64 routes are accepted, and the list hot-reloads with the rest of
the configuration.

Only declare routes that store the body as content and are protected by
authentication and output encoding. Body-borne attacks sent to a content route
are not inspected; never use a content route to exempt a public parameter
endpoint. The exemption is a local policy, not a managed rule-set field.

### Rule set format compatibility

`main` publishes the newest rule set to installs of every release, so the format
of `dist/rules.yaml` is pinned to the newest release: the published rules use
only the fields, match targets, actions, and phases that the newest released
binary implements, and adding a schema construct means cutting a release rather
than shipping it with a daily rule update. A build that meets an unknown
construct rejects the whole candidate before writing anything (no partial
application) and keeps its last known good rules, so an incompatible rule set
freezes that install's updates instead of weakening it. The failure is logged
and counted in `kunato_rules_update_incompatible_total` — alert on it, or on
`kunato_rules_last_success_timestamp_seconds` going stale, because otherwise
only a log reader notices that a server's rules stopped moving.

`scripts/check-rules-compat.sh` is the gate. It builds the newest `v*` tag,
validates `dist/rules.yaml` with that binary, and fails with the construct the
release cannot read. It runs in CI and in the daily rule-update workflow, so an
incompatible publication cannot reach `main`. Reproduce it locally with
`KUNATO_RULES_BIN=/usr/local/bin/kunato scripts/check-rules-compat.sh`, or
against a specific tag with `KUNATO_RULES_BASELINE=v0.2.0`. The unit tests in
`src/config/mod.rs` cover the rest of the publication: the file matches
`rules.example.yaml` and `dist/rules.yaml.sha256` is current.
[Daily rule updates and version compatibility](rule-updates.md) describes the
whole mechanism: the two update streams, the failure mode, the guards, the
counters an operator sees, and the release procedure for a new construct.

A rule that genuinely needs a new construct therefore takes a release:

1. add the field, target, action, or phase to the engine and document it in this guide;
2. cut a release (`v*` tag): new installs get that build, the compatibility gate
   moves its baseline to it, and the construct becomes part of the released
   format;
3. installs that want those rules upgrade by rerunning the installer. Until they
   do, they keep their previous rules and carry on protecting with them.

A version marker inside the rules file cannot replace this, because builds that
predate the marker reject unknown keys outright — the release tag (and the
channel URL an install is configured with) is the only place a build can be told
which format to expect. Supporting several releases at once would need a
per-release channel such as `dist/v1/rules.yaml`; the repository deliberately
keeps one channel and expects installs to follow releases.

Releases publish the rule set they shipped as assets, so an install can follow
releases instead of `main` and never meet a construct its binary does not
implement:

```yaml
rules_update:
  # Rules of the newest release; they change when a release is cut.
  url: https://github.com/hiroeorz/kunato/releases/latest/download/rules.yaml
  checksum_url: https://github.com/hiroeorz/kunato/releases/latest/download/rules.yaml.sha256
```

Pointing the URL at a specific tag (`.../download/v0.2.0/rules.yaml`) freezes the
rules at that release instead, which trades coverage for reproducibility.

### Category fields

| Field         | Description                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| `name`        | Unique category name.                                                                                |
| `description` | Optional free-text description.                                                                      |
| `enabled`     | Set to `false` to skip the category. Defaults to `true`.                                             |
| `phase`       | `request` (default) or `response`; selects when the category is evaluated.                            |
| `action`      | Default action (`BLOCK`, `ALLOW`, or `LOG`) for the category's rules.                                |
| `response`    | Default response for `BLOCK` rules (`status` from 200 to 599). Defaults to `403 Forbidden`.           |
| `threshold`   | Scoring mode: each matching rule adds 1 and the category action applies at the threshold.             |
| `rules`       | Ordered list of rules.                                                                               |

A category with `threshold` does not short-circuit on the first match: every
matching rule adds one point and, once the score reaches the threshold, the
category action runs (`BLOCK` or `LOG`, not `ALLOW`). Rules in a threshold
category must not set `action`, `response`, or `limit`, and the category
`action` is required. Categories without `threshold` keep first-match
semantics.

### Rule fields

| Field         | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| `name`        | Rule name, unique within the category.                          |
| `description` | Optional free-text description.                                 |
| `enabled`     | Set to `false` to skip the rule. Defaults to `true`.            |
| `action`      | Overrides the category default action.                          |
| `match`       | Conditions that must all hold for the rule to apply (required). |
| `response`    | Overrides the category response for `BLOCK` rules.              |
| `limit`       | Request-phase per-source rate limit, `{ requests: N, window: 60s }`. |

A rule with `limit` is a burst guard: the first `requests` matching requests per
`window` from one source pass through as if the rule had not matched, and later
matches take the rule's effective action (which cannot be `ALLOW`). Sources are
tracked like the automatic per-IP limits (IPv6 aggregated by
`protection.aggregate_ipv6_prefix`), allowlisted sources and
`--disable-protection` are exempt, and the state is bounded by
`protection.max_tracked_ips`. When the source table is full, stale entries are
evicted first, then the least recently seen entry without an active connection
or live ban in the source's shard; active connections and bans are retained, so
occupying the table does not deny service to every new source.

### Match fields

Match conditions are combined with logical AND; a list value means OR within that
field, and empty pattern lists (`headers: { x-required: [] }`) are rejected so a
condition can never silently disappear. At least one condition must be
specified. Regular expressions are compiled
once at load time, and an invalid pattern rejects the configuration. Path and query
values are matched raw and through up to two decode passes, so
`%253Cscript%253E`, `%3Cscript%3E`, and `<script>` all match. Queries follow
`application/x-www-form-urlencoded` conventions, so `+` is decoded to a space
(`?q=union+select` matches like `?q=union%20select`); paths are additionally
matched in normalized form at every decode stage (dot segments resolved,
duplicate slashes merged), so `//admin`, `/x/../admin`, `/%2fadmin`, and the
`/allowed/a%252fb/../../secret` shape an origin resolves to `/secret` are all
seen, not just the fully decoded form. Cookie
values are matched raw and through the same percent-decode passes, because
clients percent-encode cookie values and application frameworks decode them;
`+` stays literal in cookies, unlike queries. This applies to named `cookies`
conditions and to the `cookies` target; other header values are matched as
received. `BLOCK` and `LOG` rules match any form, so an attack hidden in one
representation is still caught. An `ALLOW` rule disables the WAF for the
request, so its trust has to be unanimous instead: it must match every path
form, every decoded form of each cookie value, every value of a repeated
`headers` or `cookies` entry, and every form of the `in` targets, and the
patterns of an `ALLOW` rule may only use `headers`, `cookies`, `response_headers`,
and `regex` values that are anchored at both ends (`^...$`); the configuration is
rejected otherwise. Anchor validation parses the regex rather than looking at its
surrounding bytes, so a top-level alternation (`^a|b$`) and an escaped dollar
(`^cost=\$`) are rejected while a grouped expression (`(?:^a$)`) is accepted. A
forged extra copy of a header and a marker appended to the
query or the body therefore cannot shadow a later `BLOCK`. `path` is exempt so a
start-anchored prefix can exempt a whole area from the rules that follow. An
`ALLOW` rule that targets `body` or `response_body` matches only when the whole
body was available for inspection; a truncated body never satisfies it. Header
values
are decoded with UTF-8 replacement, so a single invalid byte cannot hide a value
from a rule. Bodies are matched raw
and decoded by `Content-Type` (`application/x-www-form-urlencoded`, JSON string
escapes such as `\u0075`, and `multipart/form-data` flattened to field values and
`filename="..."` entries), then through the same percent-decode passes; bodies whose content
type is unknown still get the percent passes. Verified binary multipart file
payloads — a safe media claim whose bytes match that format's signature — are
content, not parameters: their bytes are masked out of the raw form and omitted
from the flattened form, so a signature such as `%{` inside compressed pixels
cannot reject a benign upload while field values, filenames, and unverified file
payloads stay in scope (the file content is inspected by
`limits.upload_inspection` instead). A
`multipart/form-data` message
that declares several boundaries is flattened once per boundary (up to four),
because parsers disagree on which one wins (Rack takes the last); messages that
exceed that fall back to the percent passes on the raw body. Bodies are
decompressed first when
`Content-Encoding` is `gzip`, `deflate`, `br`, or `zstd`: all gzip members are
decoded, repeated `Content-Encoding` fields are combined in order, and stacked
encodings are decoded in reverse order (up to three layers).
When a body rule exists, a body whose declared encoding cannot be decoded
completely within `max_body_bytes` is rejected instead of forwarded: an
over-limit decoded body returns `413`, an unsupported or over-layered encoding
returns `415`, and a malformed stream returns `400` (counted in
`kunato_request_decode_truncated_total` /
`kunato_request_decode_skipped_total`). Multipart parsing is
bounded to 64 parts with 1 KiB names and file names; a `boundary` declaration
the parser cannot read (an unterminated quote, a control or non-ASCII byte, a
token outside RFC 2046's set, or more than four boundaries) is rejected with
`400` before the body is read, so the origin cannot split the body differently
from the inspection. A quoted boundary that contains spaces is legal and is
inspected in every interpretation.

A body that declares a charset the inspection cannot read (`utf-16`, `utf-32`,
`utf-7`, or an EBCDIC code page) is rejected with `415` when body inspection is
active: decoding it as UTF-8 would show bytes, not the text the origin executes.
The check runs on the decoded body as well, so `Content-Encoding` cannot hide a
wide charset, and it recognizes a UTF-16/UTF-32 byte-order mark, the BOM-less
UTF-16/UTF-32 XML signatures, a NUL byte in a textual body, and an XML
declaration whose `encoding` names an uninspectable charset. Multipart part
charsets and `_charset_` fields are checked after decompression. Response bodies
with response-body rules are checked the same way and replaced with `502` when
they cannot be inspected. ASCII-compatible encodings such as `shift_jis` stay
accepted. No other normalization (Unicode folding, HTML entity decoding) is
performed. Body targets are skipped entirely on configured
[content routes](#content-routes).

| Field              | Description                                                                                                             |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `path`             | Regex(es) matched against the request path.                                                                             |
| `method`           | One or more HTTP methods (for example `GET` or `[POST, PUT]`); names are case-sensitive, so write them in upper case. |
| `source_ip`        | IP address(es) or CIDR range(s) the client must come from.                                                              |
| `headers`          | Map of request header name to regex(es); header names are case-insensitive.                                             |
| `cookies`          | Map of cookie name to regex(es).                                                                                        |
| `in`               | Parts searched by `regex`: `query`, `body`, `cookies`, `headers`, `path`, or `response_body`. Defaults to `[query, body, cookies]`, or `[response_body]` in a response-phase category. |
| `regex`            | Signature regex(es) searched in the parts listed by `in`.                                                               |
| `status`           | Response-phase only: status code(s) or ranges, for example `404`, `500-599`, or `5xx`.                                  |
| `response_headers` | Response-phase only: map of response header name to regex(es); header names are case-insensitive.                       |

`method` is matched against the method sent on the wire; framework method
overrides such as Rack's `_method` parameter or `X-HTTP-Method-Override` are
not resolved before evaluation. A request whose method is a case variant of a
standard method (`get`, `pOsT`, ...) is rejected with `400` before rule
evaluation, because servers that compare methods case-sensitively can be
bypassed by variant case (OpenNMS CVE-2026-111235); custom methods that are not
case variants keep their previous behavior.

Response-phase rules may combine request conditions (`path`, `method`, `source_ip`,
`headers`, `cookies`, and `in` targets) with the response-specific ones, so a rule
can require a path and a response body signature. `status`, `response_headers`, and
the `response_body` target are rejected in request-phase categories. Response
bodies with `Content-Encoding: gzip`, `deflate`, `br`, or `zstd` are decompressed
for matching (all gzip members, stacked encodings in reverse order up to three
layers), and only the first `limits.max_response_body_bytes` are inspected (the
decoded output is bounded by the same limit). Unknown or deeper encodings are
inspected as received and counted in `kunato_response_decode_skipped_total`; a
response body whose charset cannot be inspected is rejected with `502` and
counted in the same counter. A truncated response body is still inspected
best-effort but never satisfies a body-targeting `ALLOW` rule. Decoding is inspection-only: the bytes forwarded to
the upstream and to the client are never modified.

After a `101` WebSocket handshake, reassembled server-to-client messages are the
response body stream: response-phase rules that inspect `response_body` are
matched per message, with the handshake response (`101` plus its headers)
scoping `status` and `response_headers`. Rules without a `response_body`
condition are not applied to frames, and a matching `BLOCK` closes the tunnel
with `1008` rather than replacing an HTTP response.

When response-phase rules do not target `response_body`, they run as soon as
the upstream headers arrive, without buffering or waiting for response content.
Status/header rules and their LOG, ALLOW, and BLOCK actions therefore work with
streaming responses. If any response rule targets the body, prefix inspection
still precedes evaluation and preserves document order.

### Timeouts and limits

#### Form structure limits

`limits.form` is enabled by default and validates decoded `multipart/form-data`
and `application/x-www-form-urlencoded` bodies before rule evaluation. It does
not depend on automatic protection, upload content inspection, or a body rule.
`ALLOW` cannot bypass it. An incomplete form is rejected with `413`, including
in `body_inspection: stream` mode; malformed or ambiguous metadata gets `400`.
Resource-limit violations get `413`. Limits apply to actual received/decoded
bytes over HTTP/1.1 (including chunked), HTTP/2, HTTP/3, and WebSocket handshakes,
not the declared Content-Length. Forwarded bytes are never rewritten.

An ambiguous or non-canonical request head is rejected with `400` before the
body is read: duplicate `Host`, `Content-Length`, or `Content-Type` fields, a
`Content-Length` together with `Transfer-Encoding`, a non-chunked
`Transfer-Encoding`, and a non-canonical method. Duplicate `Content-Type`
matters because a parser that keeps the last field can decode a body that the
first field hid from inspection. Chunked trailer fields are dropped in both
directions: they are never inspected, so they are not forwarded either (HTTP/2
and HTTP/3 would otherwise replay them past the header limits and the rules).

| Field under `limits.form` | Default | Valid range |
| --- | --- | --- |
| `enabled` | `true` | boolean |
| `max_parts` | 64 | 1..64 |
| `max_headers_per_part` | 16 | 1..128 |
| `max_part_header_bytes` | 8192 | 1..65536 |
| `max_field_name_bytes` | 1024 | 1..4096 |
| `max_nesting_depth` | 16 | 1..64 |
| `max_fields` | 1000 | 1..10000 |
| `max_empty_files` | 16 | 1..64 |
| `max_complexity` | 4096 | 1..100000 |

Each multipart interpretation is checked independently (at most four declared
boundaries). Missing boundaries, missing closing delimiters, folded part
headers, competing Content-Type fields, duplicate disposition/name/filename
metadata, more than 64 disposition parameters, and competing `filename`/`filename*` parameters are rejected rather
than silently skipped. Ordinary quoted, single-quoted, and unquoted parameters,
empty browser file controls, and valid nested uploads remain supported. The
name-byte limit also applies to filenames. URL-encoded names are decoded once
(including `+` as space) before checking their length and nesting; duplicate
fields count independently. Values do not contribute fake field names.

Complexity charges one unit per MIME header/disposition parameter and `(nesting + 1)` per field,
multiplied by six for file metadata. This approximates PHP's repeated `$_FILES`
hierarchies; it is a bounded heuristic, not an allocator model or guarantee
against origin OOM. Defaults should be tuned against legitimate forms.

To deliberately stream forms larger than `max_body_bytes`, set
`limits.form.enabled: false` as well as `body_inspection: stream`. The remaining
upload and signature checks then inspect only the prefix. A matching PHP
profile always enforces the configured form limits, even when the global form
guard is disabled. Disabling the guard is a security tradeoff, not a mitigation.
The inspection decoder's own part/name work limits are not a substitute for
this origin-facing policy.

#### Optional PHP profile

The top-level `php` profile is disabled by default. Enabling it requires an
explicit `hosts` or `paths` scope; use `paths: [/]` to cover the whole upstream.
When both are present they are ANDed. Hosts use the same normalized allowlist
syntax as `allowed_hosts`; paths are normalized absolute prefixes matched at
segment boundaries, including decoded request-path interpretations. Scope is
based on routing, not a `.php` suffix. Use `allowed_hosts` as well when a
host-scoped upstream would otherwise serve the same application for arbitrary
Host values; host scoping cannot infer the upstream's default virtual host.

```yaml
php:
  enabled: true
  hosts: [php.example.com]
  paths: [/]
  block_multipart: false
  block_upload_progress: true
  upload_progress_names: [PHP_SESSION_UPLOAD_PROGRESS]
  session_cookies: [PHPSESSID, CUSTOMSID]
  max_session_id_bytes: 256
  session_id_pattern: '^[A-Za-z0-9,-]+$'
```

| Field | Default / meaning |
| --- | --- |
| `enabled` | `false`; opt in explicitly |
| `hosts` | omitted; optional nonempty host allowlist |
| `paths` | `[]`; up to 16 normalized prefixes, each at most 1024 bytes; `/` matches every path |
| `block_multipart` | `false`; reject multipart with `403` when the application does not use it |
| `block_upload_progress` | `true`; reject configured multipart progress field names with `403` |
| `upload_progress_names` | `[PHP_SESSION_UPLOAD_PROGRESS]`; 1..16 exact, case-sensitive field names |
| `session_cookies` | `[PHPSESSID]`; 1..16 exact, case-sensitive response cookie names |
| `max_session_id_bytes` | 256; 1..4096 decoded bytes |
| `session_id_pattern` | `^[A-Za-z0-9,-]+$`; compiled once, fully anchored, at most 4096 bytes |

Configured field/cookie names accept 1..128 ASCII letters, digits, underscores,
hyphens, and dots. Match custom progress and session names to the actual PHP
configuration. If the application uses upload progress, disable its BLOCK
explicitly; file contents mentioning the field name are not blocked.

The profile percent-decodes the configured session cookie value once, rejects
malformed encoding, excess decoded length, invalid UTF-8, and values outside the
configured pattern. Empty deletion cookies are allowed. Only configured names
are checked; Rails signed/encrypted cookies are not constrained. Custom PHP
session handlers may require a different length or character pattern.
Every Set-Cookie field is examined, and a violation replaces the entire response
with `403` without forwarding its cookies. This happens before response-body
buffering and response ALLOW, even with no response-phase rules, and before a
WebSocket tunnel is established. Changes hot-reload with the configuration.

Metrics are `kunato_form_rejected_total`, `kunato_php_request_rejected_total`,
and `kunato_php_response_rejected_total`. Rejection logs omit cookie contents.

These controls mitigate specific PHP2Shell paths, not every producer/consumer
or application-dependent OOM. Update PHP to a fixed vendor build and restart
every worker. See the [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
Form limits and the PHP profile are binary features: upgrade Kunato before
using these local configuration fields. Managed signatures continue to use the
v0.7.3 rule-set format and pass the release compatibility gate.

#### SAML message inspection

`limits.saml` decodes a `SAMLResponse` or `SAMLRequest` carried in an
`application/x-www-form-urlencoded` or JSON body and structurally checks the
decoded XML before rule evaluation. It runs independently of rule actions, so an
`ALLOW` rule cannot bypass it; only `limits.saml.mode: off` disables it. The
decoded bytes are not exposed as a rule target; the guard is the inspection
mechanism.

| Field under `limits.saml` | Default | Meaning |
| --- | --- | --- |
| `mode` | `strict` | `off`, `log` (decode and log findings only), or `strict` (reject malformed messages and high-confidence findings) |
| `max_decoded_bytes` | 1 MiB | 1..8 MiB; bound on the base64-decoded or DEFLATE-inflated message |
| `multi_assertion` | `log` | `log` or `block`; multiple plaintext assertions with different `NameID` values |
| `unsigned` | `log` | `log` or `block`; a `Response` with no XML signature anywhere |

The guard decodes standard base64; a value may carry plain XML or a
raw-DEFLATE or zlib-compressed document. XML is tokenized with an internal
subset that handles declarations, comments, CDATA, namespace prefixes, and
quoted attributes; it does not expand entities or DTDs. Element count (4096),
depth (64), attributes per element (64), and retained `NameID` bytes (4096) are
bounded. UTF-16 messages are rejected as uninspectable in `strict` mode rather
than guessed at.

In `strict` mode the guard rejects:

- a `<!DOCTYPE>` or any DTD in the decoded message (`403`),
- duplicate element ID values across the message (`403`),
- a `<Signature>` whose `<Reference URI="#...">` does not name the element that
  contains the signature, or a signature without a parent ID (`403`),
- a plaintext `<Assertion>` that is not a direct child of `<Response>` (`403`),
- malformed base64, malformed DEFLATE, malformed XML, or an over-limit message
  (`400`/`413`), and an uninspectable encoding (`415`).

`log` mode records the same findings without rejecting. The
`multi_assertion`/`unsigned` actions are independent: their engine default is
`log`, and the shipped example configuration raises `multi_assertion` to
`block`. A deployment whose identity provider legitimately sends two assertions
with different subjects must keep that action at `log` or add a local
exception path.

An application that uses a `SAMLResponse` or `SAMLRequest` field for non-SAML
data must set `limits.saml.mode: log` or `off`; `strict` rejects a value that
does not decode to XML. The guard cannot verify XML signatures or
canonicalization; it detects the structural residue of signature-wrapping and
assertion-confusion attacks. A
signed response and a signed assertion are both accepted, encrypted assertions
are not inspected, and a legitimate multi-assertion response with different
subjects can be rejected when `multi_assertion: block` is set. Update the SAML
service provider (for example SuperTokens) to the fixed release; the guard is
defense in depth, not a replacement for signature verification.

Metrics are `kunato_saml_rejected_total` for strict rejections; logged findings
are written at debug level with a `finding` field, and rejections at warn level.

#### General limits and timeouts

Durations accept `ms`, `s`, `m`, and `h` suffixes (plain numbers are seconds).
Values must fit in the unit (no silent overflow) and must not exceed 365 days.
Defaults:

| Timeout             | Default |
| ------------------- | ------- |
| `header_read`       | `10s`   |
| `body_read`         | `30s`   |
| `upstream_connect`  | `5s`    |
| `upstream_response` | `30s`   |
| `response_body`     | `5m`    |
| `shutdown_grace`    | `10s`   |
| `connection_idle`   | `60s`   |
| `websocket_idle`    | `10m`   |

| Limit                     | Default |
| ------------------------- | ------- |
| `max_path_bytes`          | 8 KiB   |
| `max_header_bytes`        | 32 KiB  |
| `max_headers`             | 100     |
| `max_body_bytes`          | 8 MiB   |
| `websocket_message_bytes` | 1 MiB   |
| `max_response_body_bytes` | 1 MiB   |
| `max_concurrent_streams`  | 100     |

Every served connection also has a write-progress deadline: a client that makes
no write progress for `connection_idle` is disconnected, so a stalled reader
cannot hold an inspection reservation or a connection slot forever. Streaming
responses must therefore make progress (or send heartbeats) within that window.
HTTP/3 response bodies also carry a total `response_body` deadline (default
`5m`), so an origin that emits a frame just inside the idle interval cannot keep
the request task and its connection slot alive indefinitely.

`max_path_bytes` bounds the whole request target (path plus query string), not
just the path. Request-target length, header size/count, and method-case checks
run before inspection memory is reserved or the body is read on all transports,
including WebSocket handshakes. An invalid head is rejected even if its declared
body never arrives. `websocket_message_bytes` bounds each reassembled
WebSocket message inspected after the `101` handshake in either direction; a
larger message closes the tunnel with close code `1009`. Kunato does not
negotiate WebSocket extensions, so frames remain uncompressed and inspectable.
Client-to-server messages are matched against body-target rules: text messages
must be valid UTF-8, binary messages are matched lossily, and rules with
per-rule limits use the same source-keyed window as HTTP. Each message is
evaluated against the configuration current at that moment, so an established
tunnel follows a hot reload and a `rules_update` without a reconnect. Server-to-client
messages are matched against response-phase rules that inspect `response_body`;
the handshake response (`101` plus its headers) scopes `status` and
`response_headers`, rules without a `response_body` condition never apply to
frames, and a matching `BLOCK` closes the tunnel with code `1008` instead of
delivering the message. Text is matched lossily in that direction without a
UTF-8 rejection, and an `ALLOW` ends evaluation for the current message only.
Inspection reserves from the process-wide 256 MiB inspection budget in both
directions; budget exhaustion closes the tunnel with code `1013`. A frame
header may declare only the bytes left in the current message, so a large
declared length cannot reserve budget ahead of the payload. Each client-to-server
message is charged to the source's request budget like an HTTP request: a rate
limit or ban closes the tunnel with `1008`, and global overload with `1013`.
`max_concurrent_streams` caps concurrent request streams per
HTTP/2 connection (and per QUIC connection for HTTP/3). HTTP/2 connections are
pinged after 30 seconds without activity and closed when the ping is not
acknowledged within 20 seconds. In addition, the first HTTP/2 request must
start within `header_read`, and a connection with no request in flight is closed
after `connection_idle`; a client that completes the TLS/ALPN handshake but
never sends a request therefore cannot hold a connection slot indefinitely.
HTTP/3 uses the same `connection_idle` value for the QUIC idle timeout, applies
`header_read` to the QUIC handshake, the HTTP/3 setup, and each request head,
and answers a QUIC Initial from an unvalidated address with a Retry before it
takes a connection slot. The process-wide inspection budget (256 MiB, reserved
from the configured body limits) bounds the total memory used by concurrent body
buffering; requests reserve a baseline share and grow it as body bytes arrive,
so a small request does not take a large body's share. A worst-case reservation
made for decoding is shrunk back to the buffers actually kept as soon as the
decoded forms are built, and follows buffered request/response bytes through
replay, clones, and slices. Response-prefix reservations are likewise shrunk to
the buffered bytes once inspection is done, so a slow reader keeps only what is
still queued. Exhausted capacity returns `503` with `Retry-After`.

`body_inspection` defaults to `strict`: when request-body rules, a GraphQL
endpoint, or multipart upload inspection need the body, the buffered prefix is
evaluated first. A matching
ALLOW rule forwards the request, a matching BLOCK rule uses its configured
response, and only when no rule decides is a request larger than
`max_body_bytes` rejected with `413`. Set the policy to `stream` to inspect the
prefix and stream the remainder instead; a warning is logged at load or reload
when body rules or upload inspection are enabled. Configurations written before
the field existed are compiled with `strict`, so add `body_inspection: stream`
to keep the old prefix-only behavior for large uploads.

Every duration must be greater than zero (`shutdown_grace: 0` would abort the
drain immediately). Limits are validated with hard caps so the "bounded
resources" invariant cannot be disabled by configuration: `max_path_bytes`
64 KiB, `max_header_bytes` 1 MiB, `max_headers` 1000, and
`max_body_bytes` / `max_response_body_bytes` 8 MiB, and
`limits.saml.max_decoded_bytes` 8 MiB.

```yaml
timeouts: { header_read: 10s, body_read: 30s }
limits: { max_body_bytes: 8388608, body_inspection: strict }
```

The first `max_body_bytes` of each request body are buffered for rule
inspection, content decoding, and upload inspection. With the default
`body_inspection: strict`, the buffered prefix is evaluated before the size
decision: a matching ALLOW rule forwards the request (the operator explicitly
trusts it), a matching BLOCK rule uses its configured response, and if neither
decides, an over-limit request is rejected with `413` because the uninspected
remainder could carry a payload past every body rule or an upload content check.
The size decision uses the bytes actually read, so a chunked or HTTP/2 / HTTP/3
body cannot bypass it. The over-limit request is counted in
`kunato_request_truncated_total`; only the strict rejection is
counted in `kunato_request_body_rejected_total`. A body exactly at the limit is
accepted.

With `body_inspection: stream`, the buffered prefix is evaluated, the remainder
streams to the upstream unchanged, and the request is counted as truncated
(`kunato_request_truncated_total`) and logged at debug level; rules then see at
most the prefix, and a warning is logged at load or reload when body rules or
upload inspection are enabled. An encoded body whose decoded output cannot be
completed within `max_body_bytes` is rejected even in strict mode, because rules
cannot safely decide on an incomplete decoded body. In strict mode, an encoded
body whose decoding completed but whose raw input exceeded the limit is
evaluated like an unencoded prefix; a matching ALLOW can forward it and
otherwise it is rejected with `413`.
Request decoding is bounded by `max_body_bytes` and response decoding by
`max_response_body_bytes`, so decompression bombs cannot exceed the configured
buffer sizes. A decoded request body that exceeds the limit is rejected and
counted in `kunato_request_decode_truncated_total`; a response prefix that was
cut off is counted in `kunato_response_decode_truncated_total` and inspected
best-effort. An `ALLOW` rule that targets a body only matches when the full
body was available, so a truncated response body cannot satisfy one.

### Host allowlist

`allowed_hosts` restricts the Host names and IP literals Kunato accepts. The
policy is disabled when the field is absent; an explicit empty list or null
value is invalid, so a typo cannot silently disable the check or take the site
down:

```yaml
allowed_hosts:
  - example.com
  - www.example.com
  - "*.example.com"     # any subdomain, never the apex
  - 127.0.0.1
  - "[::1]"
  - internal.example.com:8443
```

The policy runs after the request head is parsed and before the request body is
buffered or rules are evaluated. It checks the HTTP/1.1 `Host` header and the
HTTP/2 / HTTP/3 `:authority` when the transport exposes it; when both are
present, every source must match. Names match case-insensitively after dropping
one trailing dot. An entry without a port matches any port; an entry with a port
requires the request Host to carry the same port. A leading `*.` matches one or
more subdomain labels and never the apex; an exact entry matches only that name.
IPv4 and bracketed IPv6 literals are accepted (for example `127.0.0.1` and
`[::1]`).

A request with no Host and no `:authority`, a malformed Host or `:authority`, a
duplicate `Host` header, or an absolute-form authority that disagrees with the
`Host` header is rejected with `400`. A well-formed Host or
`:authority` that is not listed is rejected with `421`. The check is an engine
policy: an `ALLOW` rule (including `trusted-sources`) does not bypass it, it
stays active with `protection.enabled: false`, and a reload swaps the list
atomically. Rejections are counted in `kunato_host_rejected_total`.

`kunato init` writes every `--acme-domain` value into `allowed_hosts` so a new
ACME install cannot lock itself out, and accepts `--allowed-host NAME` for
additional names (the installer passes the flag through). When Kunato runs
behind a TLS-terminating proxy, list the Host value that the proxy forwards, not
necessarily the public name. Requests addressed to an IP need that literal in
the list. Adding an ACME domain by hand does not update `allowed_hosts`; Kunato
logs a warning at startup or reload when a configured ACME domain is missing
from the list. Leaving `allowed_hosts` out (or using `--cert-file` without
`--allowed-host`) keeps the previous behavior: any Host is accepted.

### Client identity behind trusted proxies

By default, request rules, rate limits, bans, and behavioral detection use the
direct connection's IP. Identity headers from an untrusted peer are ignored.
For a CDN or load balancer, configure the actual proxy addresses explicitly:

```yaml
client_ip:
  trusted_proxies: [10.0.0.10/32, '2001:db8:1::10/128']
  header: x-forwarded-for
```

| Field | Default | Meaning |
| --- | --- | --- |
| `client_ip` | omitted or null | Use the direct peer; no forwarded identity is trusted |
| `client_ip.trusted_proxies` | required when configured | 1..64 IPv4/IPv6 addresses or CIDRs for actual proxies |
| `client_ip.header` | `x-forwarded-for` | Case-insensitive selection of `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`, or `true-client-ip` |

For a trusted direct peer, the selected header is mandatory. All its field
values together must fit in 4096 bytes, including commas between repeated
fields, and contain at most 16 addresses. Only bare IPv4/IPv6 literals are
accepted: ports, brackets, unknown tokens, and empty elements are rejected.
IPv4-mapped IPv6 addresses are normalized to IPv4.

`x-forwarded-for` fields are combined in wire order and traversed from right to
left, starting at the direct peer. Trusted proxy hops are skipped; the first
untrusted address is the client. Addresses further left cannot replace that
client, but the entire header must still be valid and within the bounds.
The other three header choices require exactly one address in one field.
Missing, malformed, over-limit, or entirely trusted chains receive `400` before
body ingestion and rule evaluation, including with an `ALLOW` rule,
`protection.enabled: false`, or `--disable-protection`. There is no fallback to
the proxy IP for a trusted peer with an invalid identity assertion.

The resolved IP is used consistently by request and response `source_ip`
conditions, per-rule and per-source request limits, inspection costs,
behavioral signals, bans, and request-time `protection.allowlist` checks.
IPv6 request state is still aggregated by `protection.aggregate_ipv6_prefix`
(default `/64`). TCP/QUIC connection caps and connection-time allowlist checks
use the transport peer, because a client identity is not available at accept
time. Trusting a proxy does not exempt its clients from request protection.
Connection and client entries share the existing bounded source table. Eviction
prefers entries without a ban history, behavioral flag, or recent authentication
failure, so a flood of new addresses does not reset an attacker's escalation.

HTTP/1.1, HTTP/2, HTTP/3, and WebSocket handshakes use the same policy, resolved
anew for each request. Request decision logs distinguish `client` (resolved IP)
from `peer` (transport address). Before forwarding, Kunato removes the selected
identity header, the alternate `Forwarded`, `X-Real-IP`, `X-Client-IP`,
`CF-Connecting-IP`, and `True-Client-IP` assertions, and every
`X-Forwarded-*` field it does not write itself (including `X-Forwarded-Uri`,
`X-Forwarded-Port`, and `X-Forwarded-Prefix`). It then writes a single canonical
`X-Forwarded-For` containing the resolved client IP. `X-Forwarded-Proto`
continues to describe the connection to Kunato; this setting does not trust
forwarded scheme or host assertions.

Each trusted proxy must overwrite a single-address header or correctly append
its observed peer to XFF. Restrict the trusted ranges to actual proxies and
document direct-origin access separately; this setting is not a network access
allowlist. The block supports atomic hot reload; invalid candidates retain the
previous configuration. A valid trust-policy change does not clear existing
rate/ban state, so review active bans when migrating an existing deployment.
This is a local configuration feature, not a managed rule-set field: upgrade
the binary before adding it to an older installation.

Complete the [behavioral readiness checklist](behavioral-readiness.md) before
using behavioral `BLOCK` behind a proxy.

### Upload inspection

Multipart file parts are checked against the type they claim to be before rule
evaluation. A part that carries a `filename` is a file upload; its declared
`Content-Type` (or, when that is generic or absent, its filename extension) must
not hide an executable, server-side script, or markup payload. `mismatch` mode
rejects a part that claims an image, PDF, office document, media file, or font
(by type, or by a safe extension such as `.jpg`, `.png`, `.pdf`, or `.docx`)
while its content contains any of:

- an executable header (ELF, PE, Mach-O, a Java class, or WebAssembly) at the
  leading position;
- a server-side script marker (`<?php`, `<?=`, `<%`, a JSP `<jsp:` element, or
  a `<script runat="server">` tag) anywhere in the part, or a `#!` shebang at
  the leading position (a `GIF89a` + padding + `<?php` polyglot is caught no
  matter where the marker sits);
- active HTML/XML/SVG markup (a leading `<` after an optional BOM and
  whitespace).

A part that claims a safe type must also start with that format's signature:
JPEG (`FF D8 FF`), PNG, GIF, WebP/WAV/AVI (RIFF sub-type), BMP, TIFF, ICO, PDF
(`%PDF-` within the first 1 KiB), ZIP containers (OOXML and ODF documents), OLE
or RTF (legacy Office), MP3, MP4/MOV, Ogg, FLAC, Matroska/WebM, WOFF, WOFF2, and
SFNT fonts. Text or source code renamed to `.jpg` or `.pdf` is therefore
rejected even when it contains no script marker. A claim whose format the check
cannot verify (for example `image/heic`) still verifies the filename extension's
format; generic claims in `mismatch` mode and active-web claims are not
signature-checked, and only the leading bytes are compared, so a valid signature
followed by script code still passes.

The declared type and the filename extension must agree. A safe claim over an
executable or active extension (`shell.php` declared `image/heic`) is rejected
in both `strict` and `mismatch` mode, and in `strict` an active or explicitly
executable claim over a safe extension (`photo.jpg` declared `text/html`) is
rejected as well. Declaring both as active (`page.html` with `text/html`) keeps
working.

PHP short tags (`<?`) are detected when the tag body looks like a statement: a
variable with an assignment or member access (`$x=`, `$f(`), a function call, a
parenthesized callable (`(system)(...)`), a namespaced call (`\system(`), a
closed backtick command, or a language keyword (`echo`, `system`, `eval`,
`include`, ...) followed by an expression, after skipping whitespace, `@`, and
`/* ... */`, `// ...`, or `# ...` comments. Comments are scanned to their end,
so a long comment cannot hide the tag, and an unterminated comment runs to the
end of the part. Requiring a statement shape keeps `<?if`, `<?$x`, and `<?\`
byte coincidences inside compressed pixels from rejecting legitimate images: a
two-byte tag is common in high-entropy data and a bare name after it is not
code. ASP and JSP blocks are detected only when they close with `%>` inside a
short statement: an unclosed block is a parse error, and `<%#` or `<%=` openers
appear in compressed data by chance. This catches `<?/*x*/system(...)`, `<?=/*c*/system(...)`,
`<? \system(...)`, and `` <? `id` `` behind an image signature without matching
XML processing instructions (`<?xml`, `<?xpacket`, `<?mso-application`).

A non-multipart write request (`POST`, `PUT`, `PATCH`) whose `Content-Type` or
path names an executable or server-side script — for example
`application/x-httpd-php`, `text/x-shellscript`, or a path segment ending in
`.php`, `.rb`, or `.sh` — has its raw body scanned for an executable header, a
leading `#!`, and script markers (including short tags). This covers WebDAV and
API uploads that bypass the multipart envelope. The scan rejects with `403` and
`request body carries executable content`. The path or type only selects the
request for scanning, so a `.php` route that receives an ordinary body (JSON,
form data) is unaffected; the body content decides the rejection.

In `mismatch` mode a declared type that is itself active (`text/html`,
`image/svg+xml`, JavaScript) or explicitly executable
(`application/x-msdownload`, ...) is respected: markup behind an active claim
and an executable behind an executable claim pass. `strict`, the default, also
rejects executable and script content behind a generic or explicit executable
claim, and markup unless the part declares an active web type; an active web
part still passes its markup. `off` disables the check.

Encrypted ZIP entries, compression methods other than stored/deflate, and
BZIP2/XZ/Zstandard/7z/RAR archives are refused with `400` because the inspector
cannot bound their expansion. ZIP archives must list every local header in the
central directory, so a hybrid archive that hides a streaming-only entry is
rejected. Raw non-multipart writes that claim a safe or binary type are checked
for a matching signature and for script, executable, or archive content.

The rejection is answered with `403` (or `413` for the archive expansion
budget, or `400` for an archive claim that cannot be parsed) and counted in
`kunato_upload_rejected_total`. The check is an engine
limit: it runs before rule evaluation, so an `ALLOW` rule (including
`trusted-sources`) does not bypass it, and it stays active with
`protection.enabled: false`. It shares the multipart boundary and part limits
with rule inspection, checks every declared boundary interpretation, never
copies the body, and runs under the process-wide inspection budget. Body bytes
are charged to the source's rate budget as they arrive, and one source can hold
at most a quarter of the process-wide inspection memory, so a stalled upload
cannot exhaust the budget for every client.

```yaml
limits: { upload_inspection: strict }
```

The engine default is `strict`. Use `mismatch` (safe claims only) when the
application legitimately stores downloads, firmware, or source archives whose
bytes start with a script marker or an executable header, and `off` only where
another control covers the upload path.

An uploaded gzip or ZIP archive is also decompressed up to
`limits.upload_expansion.max_bytes` (default 64 MiB) per archive,
`limits.upload_expansion.max_total_bytes` (default 64 MiB) across the request,
and `limits.upload_expansion.max_entries` ZIP entries (default 4096) per
archive. An archive that expands past either byte bound is rejected with `413`.
A detected archive (leading gzip magic or a valid ZIP end-of-central-directory
record) that cannot be parsed is rejected with `400` rather than forwarded
uninspected. Detection is content-based, so a renamed part and a self-extracting
prefix are still inspected; a part that merely claims an archive in its type or
name but has no recognizable archive structure keeps the previous content
checks.
ZIP deflate entries are counted by their actual output, ZIP64 is read, and
encrypted or unsupported-compression entries fall back to the declared
uncompressed size. A ZIP whose end record declares zero entries but whose body
contains a local file header is rejected as malformed, while a genuinely empty
archive still passes: a streaming extractor such as Java `ZipInputStream`
follows local headers, so a zero-count central directory must not hide one.
Nested archives are not expanded. The check covers the
inspected part of the body only, so `body_inspection: stream` limits it to the
buffered prefix, and `upload_inspection: off` disables it together with the
rest of the upload checks.

```yaml
limits:
  upload_expansion:
    enabled: true
    max_bytes: 67108864
    max_total_bytes: 67108864
    max_entries: 4096
```

Archive inspection is CPU-bound, so multipart upload inspection runs on Tokio's
blocking pool rather than on an async worker. The inspected body is shared as
`Bytes` (a reference-counted handle, not a copy), a semaphore sized to the
available parallelism bounds concurrent jobs (1..=32), and the request task
waits asynchronously for a permit. A blocking task that cannot be joined is
answered with `500` instead of forwarding an uninspected body.
`kunato_upload_inspection_active` reports the jobs in flight.

The check is content-based, so an explicitly named upload (`.php`, `.rb`,
`.sh`, `.exe`) is the bundled `malicious-upload` category's job. Its
`executable-filenames`, `script-filenames`, `binary-filenames`, and
`server-config-filenames` rules match the quoted, unquoted, and RFC 5987
(`filename*=`) parameter forms and reject PHP/JSP/ASP/CGI, Ruby, extra shells
and Windows script hosts, JVM archives and shared libraries, and
`.htaccess`/`.user.ini`. Disable an individual rule in `overrides_file` when
the application accepts that file type (for example a plugin `.jar`).

In the default `body_inspection: strict`, a multipart upload larger than
`max_body_bytes` is rejected with `413` unless a rule allows the request,
because the file bytes must be complete for inspection. With
`body_inspection: stream`, only the buffered prefix is inspected and the
remainder is forwarded; a warning is logged at load or reload. The check does
not cover a file part outside the inspected prefix, a body with more than four
boundary parameters, a malformed multipart body, nested archives inside an
inspected archive, or active markup or executable headers embedded beyond the
leading bytes. The script-marker scan is linear in the inspected part size and
bounded by
`max_body_bytes`; a safe-claim file that legitimately contains `<?php` (for
example a PDF code sample) is rejected, so a deployment that must accept such
documents needs an explicit policy decision rather than a smaller scan window;
`upload_inspection: off` accepts that risk for every upload. A part without a
`filename` is a form field, not an upload, and is not checked.

### GraphQL limits

Requests to a GraphQL endpoint are checked for document depth and expanded
field count before rule evaluation. The defaults (20 selection levels and 1000
fields) are generous for normal clients; a generated query that legitimately
exceeds them can raise or disable the limits:

```yaml
limits:
  graphql:
    enabled: true
    max_depth: 20
    max_fields: 1000
    block_introspection: false
    paths: [/query]
```

An endpoint is recognized when any path segment is `graphql` or `gql`
(case-insensitive, with matrix parameters such as `;jsessionid=...` ignored),
which covers `/graphql`, `/api/graphql`, `/v1/graphql`, and `/gql`; `paths` adds
exact paths (case-insensitive, with trailing slashes and matrix parameters
ignored). Path matching runs on the percent-decoded and normalized path, so
encoded spellings and dot segments of the same endpoint are recognized. Use
`paths: [/]` when the endpoint is served at the root of a dedicated host.
`max_depth` must be between 1 and 1000, `max_fields` between 1 and 10000, and at
most 16 extra paths are accepted. `block_introspection: true` rejects documents
that select `__schema` or `__type` with `403`; it is opt-in because applications
that expose introspection legitimately need it. each path is limited to 1 KiB and must not
contain a query string, fragment, or whitespace.

The document is read from a GET `query` parameter, a form `query` field, a JSON
object or batch array, an `application/graphql` body, or the `operations` field of
a multipart upload. JSON bodies are parsed regardless of the declared content
type (the usual labels are `application/json` and `+json`), so relabelling a
query as `text/plain` does not hide it. GraphQL-over-WebSocket messages are
inspected in the tunnel too: `start` (graphql-ws) and `subscribe`
(graphql-transport-ws) envelopes are read from `payload.query`, and an
operation envelope without an extractable document closes the tunnel with
`1008` instead of being forwarded. Fragment spreads are expanded before
both the depth and the field count are computed; fragment cycles, duplicate or
undefined fragment definitions, and documents that exceed the parser's bounded
node budget are rejected. Strings, block strings, comments, variable definitions, and
argument values do not count toward the depth. A request may carry at most 256
documents (batch entries or repeated `query` fields) and the parser accepts at
most 20 000 selection nodes; larger requests are rejected as too complex.

The shape is scored statically. Every operation in a multi-operation document is
checked (an unused deep operation therefore also rejects the request), and
`@skip`/`@include` branches count toward depth and fields even when their
condition would exclude them at runtime. Both choices are deliberate: a server
that resolves `operationName` or directive conditions differently must not be
able to execute a document the analyzer did not bound.

A multipart body that does not expose a readable `operations` document — for
example one whose boundary is not among the supported interpretations, or one
that carries only file parts — is rejected with `400` rather than forwarded
uninspected, because the application's own multipart parser might still find a
document in it.

A document over either limit is answered with `400 Bad Request` and counted in
`kunato_graphql_rejected_total`. A request that cannot be inspected at all is
answered with `413 Payload Too Large` instead: a GraphQL body larger than
`max_body_bytes` is rejected rather than forwarded with an uninspected
remainder, because a second operation or a duplicate `query` field in the stream
could carry the document the upstream executes. `max_body_bytes` defaults to
the 8 MiB hard cap, so a larger GraphQL document cannot be accepted. Encoded
bodies are decoded for this check even when no body-targeting rule exists, and
an unsupported or malformed encoding is rejected (`415` or `400`) as it is for
body rules. The check is a
request-shape limit under `limits`, so `protection.enabled: false` and
`--disable-protection` do not disable it; use `limits.graphql.enabled: false`
for that.

The check covers the HTTP request that carries the document. A GraphQL
subscription transported over a WebSocket tunnel sends its operations in frames
after the `101` handshake; those frames are matched by body and `response_body`
rules but are not parsed for GraphQL depth or complexity.

### JWT algorithm policy

An application-specific JWT policy can pin the accepted header algorithms. It
is disabled by default because the WAF cannot know which algorithm an upstream
expects:

```yaml
limits:
  jwt:
    enabled: true
    allowed_algorithms: [RS256]
    require_exp: true
    allowed_issuers: [https://issuer.example]
    allowed_audiences: [kunato-lab]
    leeway: 30s
```

When enabled, `Authorization: Bearer` tokens and JWT-shaped cookie values whose
header `alg` is not in the list are rejected with `403` before rule evaluation.
`require_exp`, `allowed_issuers`, `allowed_audiences`, and `leeway` add claim
checks; signatures are not verified because the WAF does not hold the
application keys. Opaque session tokens and malformed JWTs are ignored when no
claim policy applies, so this is not a general token validator. A token that has
the three-segment JWT shape but exceeds the inspection size, or whose header
repeats a JSON key (the WAF and the application could read different values), is
rejected instead of skipped. `Authorization` separates the scheme with any
optional whitespace (including a tab), and cookies are inspected both raw and
after percent-decoding. The check is part of `limits` and therefore remains
active with `--disable-protection`. Body inspection applies the same
content-type decoding as the rule engine (form percent decoding and JSON string
unescaping), so a token written as `eyJ...%2E...` or `eyJ...\u002E...` is still
checked. Algorithm names are compared
case-insensitively after normalization; each entry is 1-32 ASCII letters,
digits, `-`, or `_`, and at most 16 entries are accepted.

### Request hardening

Optional request-shape checks cover classes that are unreliable as regular
expressions. All are disabled by default:

```yaml
limits:
  hardening:
    ssrf:
      enabled: true
      internal_hosts: [metadata.internal]
      internal_suffixes: [corp]
    duplicate_parameters:
      enabled: true
      json_keys: true
      allow_parameters: [tag]
    cache_deception:
      enabled: true
      static_suffixes: [.css, .js, .png]
      auth_cookies: [session]
    redirects:
      enabled: true
      allowed_hosts: [app.example.com]
      parameters: [redirect_uri, next]
```

`ssrf` rejects URL values whose host is a configured internal host or suffix.
Each query value, the raw body (not only its decoded forms), every decoded body
form, and every header value is searched, and all URLs in a value are examined,
so a public URL cannot hide an internal one behind it. The scan removes tabs,
CR, and LF, treats `\` as `/`, and accepts the WHATWG special schemes (`http`,
`https`, `ws`, `wss`, `ftp`, `file`) with zero, one, or two separators, so
`http:/internal`, `http:\internal`, and `http:internal` reach the same host
check as `http://internal`. A non-special `word:value` pair is not treated as a
URL.
`duplicate_parameters`
rejects conflicting duplicate query, form, multipart, and JSON fields or keys
(`+` decodes to a space in parameter names and values, matching form parsers);
`allow_parameters` exempts intentional list parameters, and multipart file parts
are not compared. `cache_deception` rejects a request for a configured static
suffix when an authentication cookie is present, checking every decoded and
normalized path form. `redirects` rejects an absolute or protocol-relative
redirect target whose host is not in `allowed_hosts` on the configured parameter
names, in query, form, multipart, and nested JSON values. Parameter names are
decoded with form rules and the PHP dots/spaces-to-underscore mapping before
comparison, so `redirect.uri`, `redirect+uri`, and `redirect%2Euri` cannot reach
the same application parameter while skipping the configured `redirect_uri`.
Control characters and surrounding whitespace are ignored and `\` is read as
`/`, matching what a browser resolves.

### Response headers

`response_headers` rewrites the headers of every response Kunato sends — upstream
responses and its own block/error responses alike — after hop-by-hop headers are
filtered. Removing identifying headers is the recommended default; replacing them
with a fixed, version-less value is the alternative:

```yaml
response_headers:
  remove: [server, x-powered-by, via]
  # set:
  #   server: webserver
```

Header names are case-insensitive, `remove` runs before `set`, and a name listed in
both is replaced rather than deleted. Hop-by-hop headers, `content-length`, and
`alt-svc` are managed by the proxy and rejected in the policy. A value in `set`
must be non-empty; use `remove` to drop a header.

### Admin and metrics

An admin listener exposes Prometheus metrics and the maintenance controls on a
loopback address. It is enabled by default even when the block is omitted;
`kunato init` writes the block explicitly so the listener is visible:

```yaml
admin:
  enabled: true
  listen: 127.0.0.1:9090
```

Set `enabled: false` to turn it off. The listener requires an explicit `Host`
that names a loopback address or `localhost`, and rejects requests carrying
`X-Forwarded-For`, `X-Forwarded-Proto`, or `X-Forwarded-Host`. Those headers are
added by the data plane, so a request forwarded from a configured upstream
cannot use Kunato as a confused deputy against its own metrics or maintenance
endpoints. Kunato also warns at startup when the upstream authority is the
admin listener itself. The `kunato metrics`, `kunato maintenance`, and
`kunato admin-access` clients strip terminal control and escape sequences from
the response before printing it.

`GET /metrics` returns the text exposition format. Counters cover total requests,
BLOCK rule hits, LOG matches, rate-limit and ban decisions, behavioral
observations and flags (`kunato_behavior_*`), global load shedding
and inspection-budget shedding, upstream failures, configuration reloads, rules
update outcomes (including
`kunato_rules_update_incompatible_total` for rule sets that need a newer build),
body truncation and decoding decisions (over-limit bodies rejected by strict
inspection: `kunato_request_body_rejected_total`; request encodings that could
not be inspected: `kunato_request_decode_skipped_total`; and response bodies
that could not be decoded: `kunato_response_decode_skipped_total`), GraphQL
rejections (`kunato_graphql_rejected_total`), and ACME
certificate issuance, cache loads, and errors; gauges cover active connections,
upload inspections running on the blocking pool, uptime, the time of the last
successful rules update, and the time of the last deployed ACME certificate. The
administrative access gate adds
`kunato_admin_access_denied_total` (requests to a declared administrative
function in the closed state) and `kunato_admin_access_allowed_total`
(requests in the open state). Non-loopback addresses are rejected at validation
time, and if the port is already in use Kunato logs a warning and continues
without the admin endpoint.

The listener also hosts the maintenance controls and the administrative access
open/close endpoints; see [Maintenance mode](#maintenance-mode) and
[Administrative access](#administrative-access).

`kunato metrics` renders the `GET /metrics` response as a bordered two-column
table with a header row: one row per sample with the metric name first and its
value second, the value column right-aligned, and the `# HELP` and `# TYPE`
comment lines omitted. Gauges whose name ends in `_timestamp_seconds` show the
local date and time in parentheses after the Unix value, or `(never)` while no
event has been recorded. It queries `127.0.0.1:9090` by default and accepts only
a loopback address through `--listen`:

```sh
kunato metrics
kunato metrics --listen 127.0.0.1:9100 | grep kunato_blocked_total
```

The command does not read the configuration file, so pass `--listen` when the
`admin.listen` value differs from the default.

### Maintenance mode

`kunato maintenance on` answers every client with the maintenance page and
stops forwarding to the upstream; `kunato maintenance off` restores normal
proxy behavior. Both commands control the running process through the
loopback admin listener, so the listener must be enabled. They use
`admin.listen` (`127.0.0.1:9090` by default) and accept `--listen <ADDR>` when
that address differs:

```sh
kunato maintenance on
kunato maintenance off
```

While maintenance mode is on, requests that pass the existing admission,
client-identity, Host allowlist, and request-head checks receive `503 Service
Unavailable` with `Retry-After: 3600` and a self-contained HTML page; request
bodies are neither read nor forwarded. The page loads the embedded
`maintenance_in_progress.png` artwork from `/maintenance_in_progress.png`,
which is the only path served the image instead of the page. A request for that
path is handled by Kunato in maintenance mode even if the origin also has it.
The switch is kept in memory, survives configuration reloads, and resets to off
when the process restarts; re-enable it after a restart while maintenance is
still in progress.

The admin listener exposes the same control as `PUT /maintenance/on` and
`PUT /maintenance/off`; `GET /maintenance` reports `on` or `off`. The
state-changing methods are not simple cross-origin requests, so a browser must
pass a CORS preflight that the admin listener never grants.

### Administrative access

`admin_access` declares named administrative functions (path groups) and a
default state for them. The gate is opt-in: it does nothing until `enabled:
true`. When it is enabled, built-in presets for common administrative
interfaces are loaded unless `presets: false`, and the default state is `open`
unless `default: close` is set. The `open` and `close` commands create
time-limited overrides; the most recently issued matching override wins, and
the configured default applies again when it expires.

```yaml
admin_access:
  enabled: true
  default: open          # open (default) or close
  presets: true          # built-in functions below; a matching name replaces one
  default_ttl: 10m
  max_ttl: 1h
  max_overrides: 64
  functions:             # optional; a matching name replaces a preset
    - name: my-admin
      paths: ['^/my-admin(?:/|$)']
      exclude: ['^/my-admin/public(?:/|$)']
```

`default: close` is the fail-closed mode: a matching function answers `404`
until an `open` override is active. `default: open` keeps normal administrative
access and lets `close` temporarily restrict it. The shipped default is `open`;
set `default: close` when the administrative surface should be unreachable
except during an explicit window.

The built-in functions are:

| Function | Covers |
| --- | --- |
| `wordpress-admin` | `/wp-admin` at any depth (including a subdirectory install), `wp-login.php`, and `xmlrpc.php`; keeps `admin-ajax.php` and `admin-post.php` public for logged-out themes and form handlers |
| `rails-admin` | Rails dev tools (`/rails/info`, `/rails/mailers`, `/rails/conductor`, `/letter_opener`), Sidekiq, PgHero, Flipper, Blazer, Delayed Job, Good Job, ActiveAdmin, RailsAdmin, Avo, and Administrate |
| `laravel-admin` | Horizon, Telescope, Nova, Pulse, Log Viewer, Clockwork, and Debugbar |
| `generic-admin` | `/admin`, `/admin.php`, `/administrator`, `/adm` (phpBB), `/-/admin` (Gitea), and `/api/.../admin` at the site root |
| `phpmyadmin` | phpMyAdmin and `/pma` |
| `adminer` | Adminer and `/adminer.php` |
| `tomcat-manager` | Tomcat `/manager` and `/host-manager` |
| `java-console` | JBoss `/jmx-console` and `/web-console`, and Axis2 admin |
| `solr-admin` | Solr |
| `spring-actuator` | Spring Boot Actuator except `/actuator/health` and `/actuator/info`, which stay public for probes |
| `nextcloud-admin` | Nextcloud/ownCloud `/settings/admin`, with or without the `/index.php` prefix |
| `ghost-admin` | Ghost `/ghost` |
| `typo3-admin` | TYPO3 `/typo3` |

The preset patterns are case-insensitive, and the product-specific names also
match a subdirectory install. `generic-admin` is root-anchored so static paths
such as `/static/admin/...` remain public; add a custom function for a panel
under a subdirectory. `wordpress-admin` gates the WordPress login; replace the
function without `wp-login.php` when the site has public user accounts. Set
`presets: false` to start from only the declared functions. A `functions`
entry with the same name as a preset replaces it, so define the complete path
and exclusion lists when customizing one. Up to 64 effective functions are
accepted, including the presets.

Open or close access from an administrative channel such as SSH on the host:

```sh
kunato admin-access close
kunato admin-access open --ttl 10m
kunato admin-access open --client 192.168.1.20 --function wordpress-admin --ttl 10m
kunato admin-access close --client 192.168.1.20
kunato admin-access status
```

With neither `--client` nor `--function`, `open` and `close` apply to every
client and every configured function. `--client` narrows the override to one
resolved client address and `--function` to one configured function. Without
`--ttl`, `default_ttl` applies; `max_ttl` is the hard upper bound.
`max_overrides` bounds the in-memory table.

Overrides are evaluated per request in issuance order: the most recent matching
override wins, so a broad `close` closes existing narrow opens, and a later
`open --client 192.168.1.20` reopens only that device while the rest stays
closed. When an override expires, the configured default applies again. The
functions hot-reload with the rest of the configuration; existing overrides
keep their expiry and are matched against the new function names. Overrides are
not persisted, so a restart returns every function to its configured default.

A request that resolves to the closed state receives `404 Not Found` with
`Cache-Control: no-store` and is not forwarded. If several functions match one
path, the request is open only when every one of them is open, so an
overlapping function cannot bypass a close. The gate is evaluated per HTTP
request; an established WebSocket tunnel is not torn down when an override
expires, so use HTTP functions for administrative actions and close the page
when finished.

The client address is the resolved identity, so with
`client_ip.trusted_proxies` an override follows the real client rather than the
proxy. Without a configured `client_ip`, all clients behind the same reverse
proxy share the peer address and therefore the override; configure `client_ip`
before relying on client-scoped overrides behind a proxy. An IP address alone
does not establish that requests belong to the same person.

Path patterns are Rust regular expressions matched against every decoded and
normalized form of the request path. A request is gated when any form matches
`paths`, so `%77p-admin`, `//wp-admin`, and `/x/../wp-admin` cannot reach the
function without the effective state being open. `exclude` patterns keep a
matching form outside the gate (for example a public AJAX handler below an
administrative prefix); exclusions are evaluated per form, so a differently
encoded form that still reaches an administrative page is not hidden by an
excluded one. Matching happens after percent decoding and dot-segment/border
normalization only; forms the origin has its own rules for, such as path
parameters (`;jsessionid=...`) or Windows trailing dots, must be covered by the
pattern. Custom patterns are case-sensitive unless `(?i)` is written; the
built-in presets already use it. Only the path is matched; an application that
selects administrative behavior from the query string or a header needs a rule
for that input in addition to the gate.

Open requests still run through the whole request pipeline: form and upload
inspection, GraphQL, JWT, and hardening checks, rule evaluation, and
response-phase rules. The gate runs before rule evaluation, so an `ALLOW` rule
cannot bypass a close. Requests the gate rejects never enter rule evaluation,
so a closed function does not spend inspection CPU, and
`kunato_admin_access_denied_total` counts them.

The configured default keeps working without the admin listener, but `open` and
`close` cannot be applied. Kunato warns at startup and on reload while the
listener is disabled. To recover from a locked-out state, set `default: open`
or `admin_access.enabled: false` and reload (the configuration watcher or
`SIGHUP`), or restart with the field changed. Enabling the admin listener
itself requires a restart, because `admin` listener settings are not applied by
a reload.

The listener exposes the controls as `GET /admin-access` (configured functions
and active overrides),
`PUT /admin-access/open?client=<IP>&function=<name>[&ttl=<seconds>]`, and
`PUT /admin-access/close?client=<IP>&function=<name>[&ttl=<seconds>]`. Every
parameter is optional; omitting `client` and `function` applies the override to
everything. The `ttl` value accepts seconds (`600`) or a duration such as
`10m`; an override outside `1s..=max_ttl` is rejected. The state-changing
methods are not simple cross-origin requests, so a browser must pass a CORS
preflight that the admin listener never grants.

The admin listener is loopback-only but has no per-user authentication: any
local process that can reach `admin.listen` can open or close access, exactly
as it can toggle maintenance. This lets the owner use an SSH session on the
host, and it also means a fully compromised upstream process on the same
network namespace can open the gate for a remote address. When local
compromise is in scope, isolate the upstream in a container or network
namespace that cannot reach the host's loopback admin port. The gate is an
access-control convenience for a single-administrator host, not a defense
against full local compromise.

### Experimental decoys

`decoys` is a local deception experiment. It serves fictional
configuration files containing credentials for a fake HTTP API also owned by
Kunato. Both endpoints are generated locally; their requests never contact the
upstream. The feature is implemented and requires a new
binary release. It does not arrive through daily rule updates.

```yaml
decoys:
  enabled: true
  token_ttl: 30m
  on_reuse: BLOCK
  issuance:
    per_minute: 60
    burst: 10
    per_source_per_minute: 6
    per_source_burst: 2
  verification: {per_second: 256, burst: 256}
  observation: {body: true}
  sites:
    - name: blog
      origin: https://blog.example.com
      sink: /_decoy/api/v1/storage/list
      presets: [dotenv, git-config, wordpress-backup]
      disabled_paths: []
      paths:
        - path: /.env.production
          template: dotenv
```

`rules.example.yaml` and `kunato init` enable these presets with `on_reuse:
BLOCK`. The example origin must be replaced with the site's public HTTPS
origin; `kunato init` instead uses the first ACME domain or allowed host when
provided. Wildcard inputs select the `blog` subdomain. Only that origin owns
the declared routes. Other domains use normal routing unless independently
restricted by `allowed_hosts`. Add more sites explicitly when needed.

`allowed_hosts` is optional. When present, the enabled site's origin must
match it; a canonical HTTPS origin also accepts an explicit `:443` entry in
the allowlist. The allowlist still enforces the actual request authority and
may reject aliases the site matcher accepts. Templates always use the
configured origin, never a client-provided host or forwarding header.

Omitting `decoys` keeps existing configurations disabled. An omitted
`on_reuse` keeps `LOG`; the explicit shipped policy chooses `BLOCK`. The table
below describes schema defaults rather than the starter policy.

| Field | Default | Validation / effect |
| --- | --- | --- |
| `enabled` | `false` | Effective only while `protection.enabled` is also true |
| `token_ttl` | `30m` | Whole seconds in 1m..24h; existing credentials retain their signed expiry on reload |
| `on_reuse` | `LOG` | `LOG` or `BLOCK`; BLOCK affects only an exact credential presented on the owned sink |
| `issuance.per_minute` | `60` | Global refill rate, 1..6000 tokens/minute, shared across sites |
| `issuance.burst` | `10` | Global bucket capacity, 1..100 |
| `issuance.per_source_per_minute` | `6` | Source refill rate, 1..600/minute, no greater than global |
| `issuance.per_source_burst` | `2` | Source capacity, 1..100, no greater than global |
| `verification.per_second` | `256` | Global HMAC-attempt refill rate, 1..4096/second |
| `verification.burst` | `256` | HMAC-attempt bucket capacity, 1..4096 |
| `observation.body` | `true` | Passive inspection of at most an 8 KiB body prefix |
| `sites` | `[]` | Required when enabled; 1..16 sites with unique names and canonical origins |
| `sites[].name` | Required | 1..64 ASCII letters, digits, periods, underscores, or hyphens |
| `sites[].origin` | Required | Explicit HTTPS origin without credentials/query/fragment or a non-root path; accepted by `allowed_hosts` when that policy is configured |
| `sites[].sink` | Required | Exact local fake API path; must not equal a trap |
| `sites[].presets` | `[]` | Individually selected preset names from the table below; no duplicates |
| `sites[].disabled_paths` | `[]` | Unique preset paths to remove; unknown removals are errors |
| `sites[].paths` | `[]` | Local `{path, template}` entries replace a preset at the same path; duplicate or simultaneously disabled entries are errors |

These limits are token buckets: capacity `B` plus rate `R` permits up to
`B + R * elapsed` operations, rather than an exact rolling-minute ceiling.
Zero does not mean unlimited. Source history is bounded by the existing
tracked-source table and uses trusted `client_ip` resolution and IPv6-prefix
aggregation. Missing tracking suppresses issuance; eviction can reset source
history while the global bucket remains bounded.

| Preset | Owned trap paths | Template |
| --- | --- | --- |
| `dotenv` | `/.env` | `dotenv` |
| `git-config` | `/.git/config` | `git-config` |
| `wordpress-backup` | `/wp-config.php.bak`, `/wp-config.php.old` | `wp-config` |
| `spring-env` | `/actuator/env` | `spring-env` |

Accept at most 32 effective traps per site and 128 across sites. Paths are
case-sensitive literal absolute paths of at most 512 ASCII bytes, using only
letters, digits, `/`, `-`, `.`, `_`, and `~`. Repeated slashes, dot segments,
percent escapes, query/fragment markers, and regex patterns are rejected in
configuration. Requests match any existing decoded/normalized path form.
Multiple matching routes return a local fallback instead of choosing one.
Canonical DNS names and default HTTPS port aliases match; nondefault ports
must match explicitly. The general Host allowlist remains authoritative and
may be stricter. Proxy-provided public-host/scheme headers are not trusted for
site selection or template substitution.

Declaring a route gives Kunato ownership for **every method** while decoys are
active. Choose paths that the real application does not need. Startup,
validation, and reload diagnostics list effective routes and warn about
administrative, content, PHP, and GraphQL overlaps. Maintenance and closed
`admin_access` functions run first; a closed Spring gate still hides the
Spring decoy. Open administrative gates do not exempt a request from inspection.

Trap GET returns `200` with a fresh credential; HEAD has the same representation
length without minting or sending one. Both consume issuance quota. Unsupported
methods/upgrades, exhausted issuance quota, missing tracking, or unavailable
inspection scratch return a small local `404`; nonce failures return `503`.
The sink normally returns `401`. An unexpired site-scoped token presented as
the entire single `Authorization: Bearer <token>` or `X-Api-Key` value qualifies
for reuse evidence. Under `BLOCK`, only that sink request gets `403`. Duplicate
fields or both authentication mechanisms are ambiguous and do not qualify.
If exact sink authentication cannot be verified within the global budget, the
sink returns local `503`. None of these responses enters upstream observation,
response-phase rules, source-ban logic, or the continuity score.

Tokens observed in query/path/cookies/Basic credentials/body or on real
application endpoints are always passive, even under `BLOCK`. A token-bearing
image URL must not ban the visitor. Regular WAF rules still apply for their
own reasons. No decoy source ban is supported, and `ban` is an unknown field.
An `ALLOW` rule does not bypass owned routes. `protection.allowlist` skips
observation/enforcement and receives token-free local `404`s on owned routes.

The total scan budget is 32 KiB of representations with at most 16 distinct
candidate/HMAC attempts. Exact sink authentication is checked first. Passive
decoding covers two percent passes, bounded Basic credentials, and supported
textual body forms. Compressed bodies reuse an already inspected decoded
prefix; decoys never force otherwise unnecessary decompression or a larger
body read. Uploaded file payloads are excluded. Work beyond the prefix/candidate/
byte limit, unsupported encodings, and established WebSocket frames can be
missed. Incomplete observation is counted and never blocks ordinary traffic.
Mandatory body buffers can reclaim optional decoy scratch before a reservation
retry; observation then stops while retaining already verified head evidence.

Every decoy response enforces no-store, noindex/nofollow, nosniff, no-referrer,
and its fixed text/JSON Content-Type after normal response-header rewriting.
Cookies, redirects, validators, compression, range metadata, and CORS headers
cannot be injected through global response settings. Verify the actual CDN
bypass policy and remove older cache objects when deploying the experiment.

The signing key is process-local and retained across reloads; restart
invalidates every old token. Expiry uses monotonic elapsed time. Removing or
renaming a site disables recognition of its credentials; restoring the same
site before expiry can restore recognition. Disable/re-enable does not rotate
the key. `--disable-protection`, `protection.enabled: false`, or
`decoys.enabled: false` disables ownership too, so those paths take the ordinary
rules/proxy path. Retain ordinary rules if the paths must remain closed then.

Structured issuance/reuse logs share a 128-bit hashed `token_id`, source,
transport peer, site, and age/lifetime metadata. The raw token is never logged;
token-bearing request paths are redacted, including two percent-decoding
layers. Issuance records creation, not confirmed receipt. Logs are bounded and
may be suppressed; IDs permit offline data correlation, not proof of the same
person or malicious intent.

Prometheus exposes `kunato_decoy_responses_total`, `tokens_issued_total`,
`reuse_total`, `blocked_total`, `limited_total`, `scan_incomplete_total`,
`invalid_tokens_total`, `token_errors_total`, and `logs_suppressed_total`, all
with the `kunato_decoy_` prefix. Labels are fixed kind/context/reason enums;
there are no per-token, per-IP, path, or site labels. The exact protocol,
counter labels, and test requirements are in [decoy design](decoy-design.md).

The bounded loopback regression also runs against a built binary:

```sh
cargo build
python3 lab/decoy_probe.py --binary target/debug/kunato --output /tmp/kunato-decoy-probe.json
```

It compares disabled/LOG/BLOCK, correlates two resolved source addresses,
asserts upstream receipts and log redaction, and checks an independent normal
client. It runs deterministic replay, not an actual LLM or a production CDN.

### Log viewer

`kunato log` reads the systemd journal for the `kunato` unit through
`journalctl` and filters the structured fields Kunato already writes. It does
not require the configuration file and does not change logging or retention:

```sh
kunato log                          # last 100 entries
kunato log -f                       # new entries only, real time
kunato log -f -n 50                 # last 50 entries, then follow
kunato log --since '1 hour ago'
```

Reading the system journal normally requires root or membership in the
`systemd-journal` group, so use `sudo kunato log` on a default install.

Options:

| Option | Meaning |
| --- | --- |
| `-f`, `--follow` | Follow new entries. Without `--lines` or `--since` it starts at the current end. |
| `-n`, `--lines N` | Number of entries to show. Non-follow defaults to 100; follow defaults to 0. |
| `--since TIME`, `--until TIME` | Passed to `journalctl`. A `--since` without `--lines` removes the implicit 100-line limit. |
| `--ip IP\|CIDR` | Match the resolved client IP; events without one fall back to the transport peer. |
| `--peer-ip IP\|CIDR` | Match the transport peer only. |
| `--attack CLASS` | Match a category-based attack class. |
| `--category NAME` | Match an exact category name. |
| `--rule NAME` | Match an exact rule name. |
| `--action BLOCK\|LOG` | Match the logged action. `ALLOW` matches are not logged. |
| `--method METHOD` | Match the HTTP method. |
| `--status CODE` | Match a recorded response status. |
| `--path REGEX` | Match the recorded `path` with a Rust regular expression. |
| `--format raw\|table\|json` | Output format. `raw` is the default. |
| `--no-color` | Disable ANSI colors in table output. |
| `-u`, `--unit UNIT` | systemd unit name (default `kunato`). |
| `--journalctl PATH` | journalctl executable (default `journalctl`). |
| `--list-attacks` | Print the supported attack classes and exit. |

All filters are optional. Repeated or comma-separated values within one option
are ORed; different options are ANDed. For example:

```sh
sudo kunato log --ip 203.0.113.9,198.51.100.0/24 --attack sqli --action BLOCK
sudo kunato log --status 429 --format table
sudo kunato log --attack cve-2025 --format json | jq .
```

#### Attack classes

`--attack` is category-based: an event has the class of its category. Use
`--category` for an exact name and `--rule` for an individual signature.
`--list-attacks` prints the authoritative list, including aliases.

| Class | Categories |
| --- | --- |
| `sql-injection` (`sqli`) | `sql-injection` |
| `nosql-injection` (`nosql`) | `nosql-injection` |
| `ldap-injection` (`ldap`) | `ldap-injection` |
| `xpath-injection` (`xpath`) | `xpath-injection` |
| `jdbc-injection` (`jdbc`) | `jdbc-injection` |
| `xss` | `xss` |
| `css-injection` (`css`) | `css-injection` |
| `ssti` | `ssti` |
| `command-injection` (`rce`) | `command-injection` |
| `path-traversal` (`traversal`, `lfi`) | `path-traversal`, `path-normalization` |
| `remote-file-inclusion` (`rfi`) | `remote-file-inclusion` |
| `ssrf` | `ssrf` |
| `xxe` | `xxe` |
| `deserialization` | `ruby-deserialization`, `python-deserialization`, `php-deserialization`, `java-deserialization` |
| `prototype-pollution` (`prototype`) | `prototype-pollution` |
| `open-redirect` (`redirect`) | `open-redirect` |
| `parameter-pollution` (`hpp`) | `parameter-pollution` |
| `mass-assignment` (`mass`) | `mass-assignment` |
| `prompt-injection` (`prompt`) | `prompt-injection` |
| `cache-deception` (`cache`) | `cache-deception` |
| `config-injection` (`config`) | `config-injection` |
| `jwt` | `jwt` |
| `malicious-upload` (`upload`) | `malicious-upload` |
| `protocol` | `protocol-anomalies`, `bad-methods`, `nginx-capture-overflow`, `webdav-and-digest` |
| `scanner` | `scanners-and-bots` |
| `brute-force` (`login-throttle`) | `login-throttle` |
| `discovery` | `api-discovery`, `admin-interfaces`, `wordpress-enumeration` |
| `exposure` | `rails-debug-endpoints`, `django-debug-endpoints`, `nextjs-dev-endpoints`, `laravel-debug-endpoints`, `vite-dev-endpoints`, `spring-actuator`, `ai-service-management`, `ci-cd-servers` |
| `info-disclosure` (`leaks`) | `sensitive-files`, `response-leaks`, `directory-index`, `default-pages` |
| `bypass` | `framework-routing-bypass` |
| `exploit` | `known-exploits` |
| `cve`, `cve-YYYY`, `cve-YYYY-MM` | every `cve-*` category |

CVE signatures living in a non-CVE category (for example `ci-cd-servers` or
`framework-routing-bypass`) take that category's class. `trusted-sources` is an
`ALLOW` category and is not logged, so it has no attack class.

#### Output

`raw` prints the `journalctl --output=short-iso` line unchanged, including the
local-time prefix. `table` prints one normalized row per matching event:

```text
TIME                      LEVEL EVENT      ACTION ATTACK         CLIENT                    METHOD PATH                           STATUS RULE                          DETAIL
2026-10-21T18:35:17+0900  WARN  reject     -      -              185.73.23.161             -      -                              421    -                             host not allowed
2026-10-21T18:36:02+0900  INFO  block      BLOCK  sql-injection  203.0.113.9               GET    /search                         403    sql-injection.union-select    request blocked
```

`json` writes one JSON object per line. Promoted fields are `journal_timestamp`,
`timestamp`, `level`, `target`, `event`, `action`, `attack`, `client`, `peer`,
`method`, `path`, `status`, `category`, `rule`, and `message`; `fields` retains
every parsed logging field, including `suppressed`, `retry_after_ms`, `signal`,
and `reason`. Missing fields are omitted. `event` is one of `block`, `match`,
`reject`, `rate-limit`, `ban`, `behavior`, or `service`.

The command reads the journal as a stream and does not buffer the full history.
It does not use a pager; pipe it to `less` when needed.

#### Rate-limit and ban logging

A source that exceeds the request budget produces one `info` line
(`event="protection.rate_limit"`) or one `warn` line
(`event="protection.ban"`) at most every ten seconds. A new ban is emitted
immediately, even when a rate-limit line was just written. The line includes
`client`, `peer`, `status=429`, `retry_after_ms`, `method`, `path`, and the
number of rejections since the previous line in `suppressed`. Individual
rejections remain at debug level, and the Prometheus counters still count every
request. This keeps per-IP 429 analysis available during a flood without one
journal write per rejected request.

For example, after a burst from `203.0.113.9`:

```sh
sudo kunato log --ip 203.0.113.9 --status 429 --format json |
  jq -c '{timestamp, suppressed: .fields.suppressed, retry_after_ms: .fields.retry_after_ms}'
```

#### Limitations

- `ALLOW` rule matches are not logged, so `--action ALLOW` is rejected.
- Query strings, headers, and bodies are not part of the log entry; `--path`
  only matches the recorded path.
- Attack classification is category-level, not per-rule metadata.
- The viewer depends on `journalctl` and the systemd journal retention policy.
- A single journal line is capped at 64 KiB before parsing. An oversized line
  is truncated and marked in the rendered output, so a local journal writer
  cannot force the viewer to allocate an unbounded line.

### TLS

Set a certificate and private key (PEM) to terminate HTTPS directly:

```yaml
tls:
  cert_file: /etc/kunato/cert.pem
  key_file: /etc/kunato/key.pem
```

Without this block Kunato serves plain HTTP. When TLS is enabled, forwarded
requests carry `X-Forwarded-Proto: https`. TLS settings are applied at startup;
changing them requires a restart. Invalid or unreadable files fail startup.

With TLS, Kunato negotiates the protocol through ALPN and prefers `h2`;
cleartext clients may use h2c prior knowledge. HTTP/1.1 clients are always
accepted, and requests are forwarded to the upstream over HTTP/1.1. Static
certificates are read once at startup; rotate them by replacing the files and
restarting, or use `tls.acme` below.

Before forwarding over HTTP/1.1, Kunato joins multiple request `Cookie` fields
with `; `, preserving their order and bytes. This includes split HTTP/2 and
HTTP/3 cookies and HTTP/1.1 WebSocket handshakes, so upstream session parsers
receive one cookie field. Rule evaluation uses the original request headers.
Response `Set-Cookie` fields remain separate.

#### Automatic certificates (Let's Encrypt)

Kunato can obtain and renew certificates automatically through the ACME
protocol (RFC 8555) without any helper process. The client is implemented
in-tree and supports TLS-ALPN-01 with P-256 ECDSA account and certificate
keys; HTTP-01, DNS-01, external account binding, and ACME renewal information
are not implemented, and the client connects directly without using
`HTTP_PROXY`/`HTTPS_PROXY` environment variables or following redirects.
Challenges are answered with TLS-ALPN-01 on the same port as regular TLS
traffic, so no extra port is needed:

```yaml
tls:
  acme:
    enabled: true
    domains: [example.com, www.example.com]
    contact: admin@example.com   # optional
    # allowed_origins: [https://certificates.example.com]  # optional, for a CA
    # that serves resources from a different origin
```

Requirements:

- every domain must resolve to this server (A/AAAA records) and TCP port 443
  must be reachable from the internet; wildcard names and setups behind a
  TLS-terminating CDN or proxy cannot be validated with TLS-ALPN-01;
- `domains` entries must be DNS names, not IP addresses (use punycode for
  international names); duplicates are rejected case-insensitively;
- URLs returned by the ACME directory and its orders are fetched only when
  their HTTPS origin (scheme, host, and port) matches the directory URL. A
  custom CA that serves nonce, authorization, challenge, finalize, or
  certificate resources from another origin must list each origin in
  `tls.acme.allowed_origins` (for example
  `https://certificates.example.com:8443`); entries are origins, not paths.

Kunato registers an ACME account (using `contact` for expiry notices when
set), answers the challenge, and serves the issued chain. Certificates renew
automatically once about two thirds of their validity have elapsed — roughly
30 days before expiry for the 90-day Let's Encrypt certificates — with
exponential backoff while the ACME server is unreachable. Transient network,
5xx, and 429 failures inside an order are retried against the same order
(honouring `Retry-After`) before a new order is created. The certificate,
account key, and a small cache metadata file are written under `cache_dir`
(default `/var/lib/kunato/acme`, created with mode 0700) so restarts keep
serving the cached certificate without contacting the ACME server again.
The cache is reused only when the certificate covers every configured domain
and has not expired; `cert.meta.json` additionally records the directory and
domain set, so changing `tls.acme.domains` or switching between staging and
production triggers a fresh order instead of serving the old certificate.
A cache written by an older release has no metadata file; it is accepted when
its subject alternative names and validity match, but its original directory
cannot be verified until the next issuance writes the metadata. Issued
certificates must list every configured name as a subject alternative name;
CN-only certificates are not deployed.

Issued certificates are parsed normally by rustls. If a private CA includes a
critical extension that webpki does not understand, Kunato falls back to
verifying the certificate's SubjectPublicKeyInfo against the private key and
serves the chain opaquely, preserving compatibility with private CAs. A CA
response with an unsupported chain of more than 10 certificates or 64 KiB is
rejected.

Set `staging: true` to use the Let's Encrypt staging directory (untrusted
test certificates), or `directory: https://…` for a custom ACME directory such
as an internal CA; the two cannot be combined and `directory` must be an
`https://` URL. `contact` is optional and may be given with or without the
`mailto:` prefix.

On the first start the certificate is ordered asynchronously and TLS
handshakes fail until it has been issued (a few seconds). On later starts the
cached certificate is loaded before the listener starts accepting connections.
`tls.acme` is applied at startup like the rest of the `tls` block; changing it
requires a restart. The certificate cache lives under the service state
directory, so keep `StateDirectoryMode=0700` (set in the packaged unit) and
`cache_dir` writable by the service user.

`scripts/acme-pebble-test.sh` runs the integration tests for issuance, HTTP/3
serving, renewal, and cache reuse against a local
[Pebble](https://github.com/letsencrypt/pebble) server in Docker.

### HTTP/3

HTTP/3 over QUIC is opt-in and requires a `tls` block:

```yaml
http3:
  enabled: true
  listen: 127.0.0.1:8443   # optional; defaults to `listen`
```

When enabled, Kunato binds a UDP socket and terminates HTTP/3 with the same
certificate and key. The UDP address defaults to the TCP `listen` address, so
under normal deployments both share one port. TCP responses then carry an
`Alt-Svc: h3=":<port>"; ma=86400` header so clients can discover HTTP/3.

HTTP/3 requests pass through the same protection, limits, and rule evaluation
as TCP requests. HEAD responses carry no content, including Kunato-generated
block and error responses. QUIC active migration is disabled: client identity,
per-source limits, and source allowlists are keyed by the address the
connection was admitted from, so a client that changes its path address must
open a fresh connection. Settings are applied at startup (like TLS); changing or
disabling them requires a restart. If the UDP socket cannot be bound, Kunato
logs a warning and keeps serving over TCP.

### WebSocket

Kunato forwards HTTP/1.1 WebSocket handshakes (`Upgrade: websocket`) to the
upstream. The handshake request is evaluated by the same protection budgets and
rules as any other request, and is blocked like one; when the upstream answers
`101 Switching Protocols`, Kunato opens a bidirectional tunnel between client
and upstream.

Handshake headers use the same filtering as ordinary HTTP. A `Connection` token
that names an end-to-end field (including `Origin`, `Cookie`, or a custom
header present on the request) is rejected with `400` before the handshake, so
the inspected header set cannot differ from the forwarded one. Standard
hop-by-hop fields are removed, then `Connection: upgrade` and
`Upgrade: websocket` are rebuilt for the forwarded handshake.

Application payloads are inspected in both directions. Client-to-server
messages are reassembled (up to `limits.websocket_message_bytes`) and matched
against body-target rules; the opt-in `limits.jwt` policy also checks each
client message, as does the GraphQL limits check on a recognized GraphQL path.
Server-to-client messages are reassembled the same
way and matched against response-phase rules that inspect `response_body`, with
the `101` handshake response scoping `status` and `response_headers`. A matching
`BLOCK` closes the tunnel with `1008`; malformed frames close with `1002`, an
oversized message with `1009`, and inspection-budget exhaustion with `1013`.
WebSocket extensions are not negotiated, so compressed frames are never
accepted. `max_body_bytes` still does not apply to tunnel frames. Tunnels with
no traffic in either direction are closed after `timeouts.websocket_idle`
(default `10m`), and all tunnels are closed on shutdown. WebSocket over HTTP/2
or HTTP/3 (extended CONNECT) is not supported: a `CONNECT` request is rejected
with `405` at head validation, before any body is read.

### Hot reload

Kunato watches the configuration file plus the configured `rules_file` and
`overrides_file` for changes. When any of them is updated:

- The new configuration is parsed and validated **before** it is applied.
- A valid configuration is swapped in atomically; in-flight HTTP requests are
  unaffected, while established WebSocket tunnels apply the new rules to each
  subsequent message.
- Reloads are serialized across the file watcher, SIGHUP, and the rules updater,
  and the parse/compile runs on a blocking worker, so two reloads cannot store
  snapshots out of order and the async workers keep serving during a refresh.
- An invalid configuration is rejected and the last known good rules remain active,
  with the error reported in the logs.

## DoS / DDoS Protection

Kunato monitors connection and request rates to detect abusive traffic. When a
source exceeds the configured thresholds, it is automatically throttled and, after
repeated violations, temporarily banned. Detection and mitigation run without
manual intervention and are independent of the YAML rule set.

```yaml
protection:
  enabled: true
  allowlist: [10.0.0.0/8, 192.168.0.0/16]
  max_connections_per_ip: 32
  max_connections: 1024
  requests_per_second: 20
  burst: 60
  global_requests_per_second: 2000
  max_tracked_ips: 100000
  aggregate_ipv6_prefix: 64
  ban:
    violations: 5
    window: 10s
    duration: 60s
    max_duration: 1h
  behavior:
    enabled: true
    window: 60s
    min_requests: 30
    enumeration:
      enabled: true
      action: BLOCK
      not_found_ratio: 0.5
      distinct_paths: 40
    auth:
      enabled: true
      action: LOG
      min_failures: 20
    global_auth:
      enabled: true
      window: 60s
      min_failures: 100
      action: BLOCK
      ban: 60s
    scraping:
      enabled: true
      action: BLOCK
      min_requests: 40
      distinct_paths: 40
    sequence:
      enabled: true
      action: BLOCK
      short_window: 10m
      long_window: 24h
      half_life: 6h
      threshold: 12
      min_windows: 2
      min_dimensions: 2
      ban: 5m
```

The per-IP limiter uses a token bucket (`requests_per_second` refill rate, `burst`
capacity). Exceeding it returns `429 Too Many Requests` with a `Retry-After`
header; exceeding the global rate or connection budget returns `503 Service
Unavailable`. Connection-budget rejections are written as `503` on plaintext
listeners; a TLS listener closes the connection before the handshake instead,
because completing it is the work the budget is meant to avoid. HTTP/3 refuses
the QUIC connection. Repeated violations trigger a ban that doubles on each
recurrence up to `max_duration`. Addresses in `allowlist` bypass all protection
limits.

`scraping` counts distinct `200` responses on non-static paths per source and
flags a source that crosses both `min_requests` and `distinct_paths`. It is
opt-in because API clients and legitimate crawlers can look similar.

`sequence` accumulates weighted evidence for one source across a short and a
long window. The short window resets on activity-driven rollover and only feeds
the log line; the long score decays with `half_life`. The action requires
`score >= threshold`, at least `min_dimensions` distinct evidence kinds, and
activity in at least `min_windows` short windows, so one burst cannot ban. The
weights are 1 for an upstream `404`, 2 for an upstream authentication failure,
3 for a rule `BLOCK` or the closed `admin_access` gate, 4 for a structural
rejection, and 6 for a rate-limit ban, plus 4 for a retry of a known target in
a different encoding and 3 when a second attack category appears. A
`sequence` `BLOCK` bans for `ban`, escalated up to `ban.max_duration`, then
resets the evidence.

`global_auth` aggregates authentication failures across sources. With the
default `action: LOG` it only records the threshold; with `action: BLOCK` it
blocks subsequent requests on the configured `auth.paths` for `ban` from the
sources that contributed a recent failure themselves. A clean source is not
locked out, so one attacker cannot deny authentication to every user. The block
is not a per-source ban and does not identify individual stolen credentials.

Admission consumes one token. Body bytes are charged as they arrive, one token
per 256 KiB, capped at 64 tokens per request; decompression above the wire size
is charged when the decoded body is inspected. Each source also holds at most a
quarter of the process-wide inspection-memory budget, so a stalled body cannot
reserve it all. A 1 MiB body therefore costs
about five tokens, and the global limit is charged the same way. This ties the
CPU cost of body rules to the rate budget instead of counting a 1 MiB request
the same as a small one.

GraphQL depth and field limits (see "GraphQL limits") also run automatically,
independent of the YAML rule set. They are configured under `limits` rather than
`protection`, so they stay active when rate limits and bans are disabled.

IPv6 clients are tracked by the `aggregate_ipv6_prefix` prefix (default 64) rather
than by full address, so rotating within a prefix cannot bypass rate limits, bans,
or per-IP connection budgets. Set it to 128 to track each address separately;
IPv4-mapped addresses (`::ffff:a.b.c.d`) are always treated as IPv4.

Protection rate limits and bans can be turned off entirely with
`protection.enabled: false`, or at
runtime with `--disable-protection`. The flag also survives configuration reloads,
so it is a convenient way to run load or black-box tests without rate limits and
bans interfering.

### Behavioral detection

Kunato also keeps a per-source, tumbling behavior window over upstream response
statuses. It runs after the upstream response and before response-phase rules,
so it uses the status the application actually returned and never observes
Kunato's own block or error responses. The engine defaults to observation only:
flags are logged and counted, and no traffic is blocked until a signal's
`action` is raised to `BLOCK`. The shipped policy (`rules.example.yaml` and the
`kunato init` template) raises every signal to `BLOCK`, and that stays the
release default; lower a signal to `LOG` where its false-positive rate is not
yet understood.

- **Enumeration** counts `404` responses on non-static paths and estimates the
  number of distinct paths in the window. A source is flagged when it meets all
  three conditions: `min_requests`, `not_found_ratio`, and `distinct_paths`.
  Static assets, source maps, and common crawler files are excluded from the
  `404` count so a normal page load with a missing asset does not look like a
  scanner.
- **Authentication abuse** counts `401`/`403` responses on login, token,
  session, MFA, and SSO paths. The built-in path list covers the bundled
  `login-throttle` paths plus common API and SSO forms; replace it with
  `auth.paths` when the application uses different endpoints. Paths are
  normalized and percent-decoded before matching, so `//login` and `%6cogin`
  are still recognized.
- **Global authentication abuse** sums `401`/`403` authentication failures
  across all sources. This is the signal for distributed spraying where each
  source stays below the per-source threshold. With `action: BLOCK` it rejects
  authentication paths for `global_auth.ban`, but only for sources that
  contributed a recent failure themselves, so one attacker cannot lock every
  user out of the login page. The engine default stays `LOG`; the shipped
  policy sets `BLOCK`.
- **Scraping** (opt-in) counts distinct `200` responses on non-static paths and
  bans a source walking many pages. The shipped policy enables it with
  `BLOCK`; it is the most aggressive signal and the first one to lower to `LOG`
  for a public blog with heavy legitimate browsing.
- **Cross-request continuity** (`sequence`) scores weighted evidence across a
  short and a long window with decay. Upstream `404`s and authentication
  failures count, and so do the requests Kunato rejects itself: rule `BLOCK`s,
  structural rejections, the closed `admin_access` gate, and rate-limit bans.
  A retry of a known target with a different encoding and a switch to a second
  attack category add bonus weight. The action requires `min_windows` short
  windows with activity and `min_dimensions` evidence kinds, so neither a
  single burst nor one noisy signal can ban on its own. State is fixed-size and
  decays lazily; a `BLOCK` bans for `sequence.ban`, escalated like any other ban.

A per-source `BLOCK` flag applies a ban after the current response, using the
same `ban.duration` and escalation as a rate-limit ban; the next request from
that source receives `429` with `Retry-After`. The current response is forwarded
unchanged. Any ban (behavior or rate limit) resets the source's behavior window
so a resumed attack starts from zero.

`protection.enabled: false` and `--disable-protection` disable behavioral
detection as well. `protection.allowlist` exempts a source; an `ALLOW` rule,
including the bundled `trusted-sources` category, does not. The state is inline
in the existing tracked-source table and remains bounded by `max_tracked_ips`
(about 7 MB at the default 100 000 sources).

Limitations:

- Behind a CDN or load balancer, configure and verify `client_ip` before
  enabling `BLOCK`; otherwise every client shares the proxy's source address.
- A slow prober below every threshold is not detected. A scraper that only
  receives `200` responses is not detected either; both remain rate-limit and
  rule-set responsibilities.
- Distributed enumeration is not detected; only distributed authentication
  failures have a global signal.
- The flag log is deduplicated per source, signal, and window. Metrics are
  available as `kunato_behavior_not_found_total`,
  `kunato_behavior_auth_failures_total`,
  `kunato_behavior_enumeration_flags_total`, `kunato_behavior_auth_flags_total`,
  `kunato_behavior_global_auth_flags_total`, and
  `kunato_behavior_blocked_total`.

## Fault Tolerance

- Invalid rule reloads never take down a running instance.
- A failed rules update (network, checksum, validation) always keeps the current
  rule set active.
- Upstream failures and timeouts are handled gracefully.
- Request handling paths avoid panics and unbounded resource usage.
- Graceful shutdown drains in-flight connections.

## Roadmap

- [x] Project scaffolding
- [x] Reverse proxy core
- [x] Rule engine (`BLOCK` / `ALLOW` / `LOG`)
- [x] YAML loader and hot reload
- [x] DoS / DDoS detection and mitigation
- [x] Metrics endpoint and admin listener
- [x] Example configuration, systemd unit, and static musl builds
- [x] Optional TLS termination
- [x] HTTP/2 (ALPN over TLS, h2c prior knowledge)
- [x] HTTP/3 over QUIC (opt-in, Alt-Svc advertisement)
- [x] Host/authority allowlist (`allowed_hosts`)
- [x] Administrative access open/close overrides (`admin_access`)
- [x] Behavioral bot and authentication-abuse detection
- [x] Response-phase rules (status, response headers, response body)
- [x] curl installer and managed rule set with daily updates
- [ ] Detached signatures (minisign) for rules updates

## Contributing

This is a personal project, but issues and pull requests are welcome. Please keep
all code, comments, and documentation in English. Before opening a pull request,
run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`
(or `./scripts/check-deny.sh` in a read-only environment), and `cargo test`.
