# Monitoring console: Phase 6 remote access

Date: 2026-11-16

Status: Implemented on top of [Phase 5](monitoring-console-phase5.md).
`src/console/server/auth.rs` owns the token, sessions, and login limiting;
`src/console/server/mod.rs` enforces the source allowlist, Host validation,
TLS, and security headers; `src/proxy/tls.rs` loads the console certificate,
including a combined key-and-chain bundle. It does not expose any
administrative write operation. The packaged `kunato-console.service` and
installer enablement are implemented; the service account/certificate
permission procedure remains future work.

## 1. Scope

| Control | Phase 6 contract |
| --- | --- |
| Listener | Loopback by default; a remote listener is explicitly configured |
| Source allowlist | IPv4/IPv6 CIDRs checked against the transport peer for every route |
| Host validation | DNS-rebinding protection using `console.allowed_hosts` |
| Authentication | Single operator token, login, server-side session, logout |
| Transport | TLS 1.2/1.3 with HTTP/1.1 only on the console listener |
| Certificate material | PEM chain plus key, or the combined ACME cache bundle |
| Failure posture | Remote configuration without any control fails loading |

No login, session, allowlist, or certificate feature changes the WAF request
path. The console remains read-only.

## 2. Fail-closed configuration

A non-loopback `console.listen` requires all of:

1. `console.auth.enabled: true`.
2. `console.tls` with a readable certificate and key bundle.
3. A non-empty `console.allowed_clients`.
4. A non-empty `console.allowed_hosts`.

Each missing control is reported as a separate configuration error. A loopback
listener accepts any combination, so SSH forwarding and local review work
without TLS. Enabling a control on a loopback listener still enforces it.

```yaml
console:
  enabled: true
  listen: 0.0.0.0:9091
  source: 127.0.0.1:9090
  storage_dir: /var/lib/kunato/console
  allowed_clients:
    - 127.0.0.1/32
    - ::1/128
    - 192.168.1.20/32
  allowed_hosts:
    - console.example.com
  auth:
    enabled: true
    token_file: /var/lib/kunato/console/console-token
  tls:
    cert_file: /var/lib/kunato/acme/cert.pem
```

`allowed_clients` is separate from the WAF protective allowlist and from the
WAF request `allowed_hosts`. Adding a remote client does not make a loopback
listener reachable from a remote network.

## 3. Source allowlist

- The check uses the actual TCP peer address. `X-Forwarded-For` and similar
  headers are never trusted; requests carrying the WAF forwarding markers are
  rejected before routing.
- IPv4-mapped IPv6 peers are normalized to IPv4 before matching, so
  `::ffff:192.0.2.10` matches `192.0.2.10/32`.
- An empty `allowed_clients` permits loopback peers only.
- A denied peer receives a plaintext `403` before TLS and the connection
  closes. The decision covers pages, assets, APIs, login, and the live stream;
  reconnects are checked again.
- At most 256 entries are accepted; host bits are cleared during parsing.
- Denials are logged at `warn` with the peer address, without request headers or
  query values.

## 4. Host validation

- With `console.allowed_hosts` configured, the `Host` header must match one of
  the entries using the existing `allowed_hosts` semantics (wildcards, ports,
  IPv4/IPv6 literals).
- A missing, malformed, duplicate, or unlisted Host gets `421` for a well-formed
  but unlisted name and `400` otherwise. The same rule applies to every route.
- Without the list, a loopback listener accepts only loopback names and
  addresses, preventing a browser from reaching the console through an
  attacker-controlled DNS name that resolves to `127.0.0.1`.
- The list is intentionally separate from the WAF request `allowed_hosts`
  because the console commonly uses a private name.

## 5. Authentication

### 5.1 Credential

- The credential is a random 256-bit token rendered as 64 lowercase hex
  characters.
- `console.auth.token_file` defaults to `<storage_dir>/console-token` when
  authentication is enabled.
- A missing file is created atomically with mode `0600` inside the existing
  console storage directory. The token is never logged.
- An existing file must be a regular file, 32..512 bytes after trimming
  whitespace, with no control characters. A group- or world-readable token
  produces a warning but is not silently rewritten.
- Comparison uses a constant-time equality check.
- The token is read once at startup. Rotating it requires a console restart;
  sessions issued under the old token are process-local and end at restart.

### 5.2 Login

`POST /api/v1/session` with `Content-Type: application/json` and a body of at
most 4 KiB:

```json
{"token": "<64 hex characters>"}
```

- Success returns `200 {"authenticated":true}` and sets the session cookie.
- A wrong token returns `401 {"error":"authentication failed"}` with no
  distinction between missing and incorrect input.
- More than 5 failures from one address within 60 seconds return `429` with
  `Retry-After: 60`. The limiter holds at most 1,024 addresses; expired entries
  are pruned first.
- Query parameters, other content types, malformed JSON, and oversized bodies
  are rejected with `400`, `413`, or `415`.
- Login is not available when authentication is disabled; the session endpoint
  reports `{"enabled":false,"authenticated":true}`.

### 5.3 Sessions

- A session identifier is 256 random bits, stored only on the server in a
  bounded table of 64 entries with a 12-hour idle-independent lifetime.
- Cookies are `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` when TLS is
  active. With TLS the cookie name is `__Host-kunato_console`; without TLS it is
  `kunato_console` because the `__Host-` prefix requires `Secure`.
- Issuing a new session prunes expired entries and drops the entry closest to
  expiry when the table is full.
- Requests are authenticated by a valid session cookie or, for non-browser
  clients, `Authorization: Bearer <token>`. Bearer authentication does not
  create a session.
- `GET /api/v1/session` returns `{"enabled":true,"authenticated":true|false,
  "tls":true|false}` and is safe to call before login.
- `DELETE /api/v1/session` revokes the server-side session and expires the
  cookie. It is idempotent.
- Unauthenticated API and SSE requests return `401`; unauthenticated `GET /`
  redirects to `/login`. No state-changing endpoint exists beyond session
  management, and `SameSite=Strict` blocks cross-site cookie use.

## 6. TLS

- `console.tls.cert_file` is the PEM certificate chain. `key_file` is the PEM
  private key; when it is omitted, the private key is read from the same file.
  This supports pointing `cert_file` at the WAF's ACME cache `cert.pem`, which
  contains both the key and the chain.
- ALPN offers `http/1.1` only. The console does not serve HTTP/2 or HTTP/3.
- TLS 1.2 and 1.3 are accepted with the ring provider and safe defaults.
- Material is loaded at startup. Before each accepted connection the file
  metadata is checked; a changed size or modification time triggers a rebuild.
  A rebuild failure keeps the previous configuration and logs the error. Checks
  are throttled to one rebuild attempt every 5 seconds.
- A handshake fails closed: there is no plaintext fallback and no redirect from
  a remote listener to HTTP.
- Private-key files that are readable outside their owner and group produce a
  warning, matching the WAF TLS behavior.
- The console never reads or copies the ACME account key. If the console runs as
  a different account than the WAF, the operator must grant read access to the
  certificate bundle through file ownership or an installed copy; the console
  does not widen the cache permissions itself.

## 7. Security headers and request bounds

Every routed response carries:

- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
- `Cache-Control: no-store` for APIs and the live stream

The login page uses only same-origin assets and external resources are not
loaded. Event values are inserted with `textContent`, never as HTML. Paths are displayed as returned
by the source (query strings are not stored).

Additional bounds: 128 concurrent connections, 16 live streams, 4 KiB login
body, 10-second header read, 25 ms SQLite busy timeout inherited from the
storage layer, and a 5-second shutdown drain.

## 8. Failure behavior

| Situation | Behavior |
| --- | --- |
| Token file unreadable or malformed | Startup fails; no console is served |
| Token file missing | Created 0600 and startup continues |
| Certificate missing or invalid | Startup fails for a remote listener; no plaintext fallback |
| Renewed certificate appears | Next connection after the metadata change uses it when the rebuild succeeds |
| Certificate rebuild fails | Previous material stays active and the error is logged |
| Source allowlist or Host check fails | `403`/`421` before routing; no session or health data leaks |
| Too many login failures | `429` for the bounded window; other clients are unaffected |
| Session table full | Oldest/first-expiring session is dropped; the client logs in again |
| Console restart | Sessions end; the token file and history remain |

## 9. Verification

Implemented checks:

- Configuration (`src/config/mod.rs` test): a remote listener reports each
  missing control separately; loopback configurations stay valid; CIDR and host
  parsing; combined bundle; token file default.
- Allowlist (`tests/console_server.rs`): a non-listed loopback peer receives
  `403` before routing; the check runs at accept time for every route.
- Host and forwarding markers: missing Host `400`, foreign Host `421`,
  `X-Forwarded-For` `400`.
- Authentication: token file creation and mode, wrong and correct token,
  session cookie attributes, bearer access, logout revocation, and `429` after
  five failures with `Retry-After`. Unit tests cover expiry, revocation,
  symlinked/oversized credential rejection, and per-address limiting.
- TLS: self-signed handshake with a combined key-and-chain bundle, HTTP/1.1
  response, and `"tls":true` in the session response. Reload behavior is
  implemented by file-stamp comparison with a throttled rebuild; it is covered
  by review rather than an automated multi-second test.
- Headers and bounds: CSP, `nosniff`, `no-referrer`, `X-Frame-Options`, and
  `no-store` are applied centrally; stream and connection limits are constants
  enforced by semaphores.

Review notes: the remote configuration fails closed at load time; the token is
compared in constant time, created with mode 0600, never logged, and rejected
when it is a symlink or oversized; sessions are server-side, bounded, and
expire; the allowlist uses the transport peer and runs before TLS; forwarding
markers are rejected before routing; TLS has no plaintext fallback and keeps the
previous certificate when a reload fails; and the console never reads the ACME
account key or changes cache permissions.

Final verification ran `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
`./scripts/check-deny.sh`, and `cargo test` in that order: 1,252 tests passed
with three existing external ACME tests ignored. The authentication, allowlist,
Host, and TLS checks in `tests/console_server.rs` and the auth unit tests are
part of that run.

Remaining verification: an installed service under a separate account, real
ACME renewal reload, IPv4/IPv6 and IPv4-mapped peers on a remote listener, and
proxy-fronted deployments.

## 10. Remaining after Phase 6

Service identity and certificate permissions for a separate service account,
supported online backup and schema upgrades, and the deferred items in
[remaining work](monitoring-console-remaining.md). The systemd unit and
installer enablement are implemented.
