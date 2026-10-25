# Attack coverage tracker

Status of common WAF attack classes against the bundled set shipped with Kunato
(`rules.example.yaml`, mirrored by `dist/rules.yaml`) and the mechanisms in
`src/` (rule engine, protocol/resource limits, protection). Snapshot date:
2026-10-25; the managed set carried 492 rules then.

This file is a living tracker: update the verdicts and evidence whenever the
bundled rules or the engine capabilities change (see the "Attack Coverage
Tracking" section in `AGENTS.md`).

Legend:

- ✅ **Covered** — bundled rule or built-in mechanism stops the attack.
- 🔶 **Partial** — limited (CVE-specific only, mitigation only, or conditional).
- ❌ **Gap** — nothing bundled; most gaps can be closed with local YAML rules.

Note: the engine matches `path`, `method`, `source_ip`, `headers`, `cookies`,
`regex` over query/body/cookies/headers/path/response_body, `status`,
`response_headers`, plus `threshold` categories and per-rule `limit`, so a ❌
often means "no signature shipped", not "impossible". Engine checks outside that
match language — GraphQL depth/complexity, strict body sizing,
`limits.upload_inspection`, the `allowed_hosts` Host/authority policy, and the
`protection.behavior` source/authentication signals — address classes no regex
expresses. `content_routes` is an explicit local opt-out of body-targeting rules
for authored-content endpoints rather than a coverage mechanism, so it removes
body coverage on those routes and does not change the bundled verdicts.

## 1. Injection

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| SQL Injection | ✅ | `sql-injection`: UNION (including padded `/*...*/`, `--`, and `#` comments between UNION and SELECT, closed after the local lab bypassed a fixed 20-character gap), boolean, stacked, time-based (comment-obfuscation resistant), blind inference, executable comments, metadata functions |
| NoSQL Injection | ✅ | `nosql-injection`: Mongo operators (`$where/$ne/$regex`, ...) |
| OS Command Injection | ✅ | `command-injection`: shell metacharacters plus command words, `$()`/backticks, brace expansion, `/bin/`, `cmd.exe`, `powershell`, and bash `/dev/tcp` reverse shells (HestiaCP CVE-2026-111627) |
| JDBC Injection | ✅ | `jdbc-injection`: MySQL/MariaDB file-read and deserialization parameters (`allowLoadLocalInfile`, `allowUrlInLocalInfile`, `autoDeserialize`) and H2/HSQLDB `INIT=RUNSCRIPT`/`CREATEALIAS` in a caller-supplied `jdbcUrl` (AllData CVE-2026-111613, Apache Kylin CVE-2026-68571); benign datasource URLs keep passing |
| PHP Configuration Injection | ✅ | `config-injection.php-ini-directives` blocks `auto_prepend_file`/`auto_append_file` values and `allow_url_include=on` reaching php.ini (pfSense CE timezone CVE-2026-111222) |
| LDAP Injection | ✅ | `ldap-injection`: filter breakout (`*)(`, `)(\|(`, `)(attr=`), operator chains (`\|(uid=`, `&(cn=`), wildcard attributes (`(objectClass=*`, `(userPassword=*`), and wildcard credentials on the login paths (`*` as the whole value or anywhere in a user/uid/email parameter); query/body/cookies/headers, plus and percent encodings included |
| XPath Injection | ✅ | `xpath-injection`: predicate breakouts (`']//`, `'] \| //`, `or //user[...]`), blind-inference functions (`count(/*)`, `string-length(name(/*[1]))`, `substring(//...)`, `contains(//...)`), quote-based function probes (`or name(`), and string taunts (`or '1'='1`, `or ''='`); numeric taunts (`or 1=1`) are also covered by `sql-injection` |
| XML Injection | 🔶 | XXE (`<!DOCTYPE[`/`<!ENTITY`) is generic and blocked; generic XML structure injection and SOAP deserialization are CVE-specific |
| SSTI | ✅ | `ssti`: generic arithmetic probes and engine gadgets for Jinja/Twig (`{{7*7}}`, dunder access), Freemarker (`<#assign`, `?new()`), Velocity (`$class.inspect`, `#set($`), ERB/JSP (`<%=`), Thymeleaf (`*{}`), and Smarty (`{7*7}`); `${`/`%{` are covered by `cve-2019-signatures.struts-expression-injection`; the CVE-specific set is retained |
| Expression Language Injection | 🔶 | Same: CVE-specific (Ivanti EPMM, Struts OGNL, Nexus JavaEL, ...) |
| CRLF Injection / HTTP Header Injection | ✅ | `protocol-anomalies.crlf-injection` (`%0d%0a` etc. in path/query/headers) |

## 2. XSS and Browser-Side

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Reflected XSS | ✅ | `xss`: script/iframe/object/embed, broad event-handler list, `javascript:`/`vbscript:`, `data:text/html`, DOM sinks |
| Stored XSS | 🔶 | Input-side detection uses the same rules and `xss` matches header values, so header-injection stored XSS (Crafty Controller CVE-2026-18516) is stopped at the input; output-time context escaping is the application's job. `response-leaks` ships no XSS signatures |
| DOM Based XSS | 🔶 | `dom-sinks` (`document.cookie`, `eval(` etc.) exists but the root cause is client-side |
| HTML Injection | 🔶 | script/iframe-like tags are blocked; generic tags (`<div>`) pass |
| JavaScript Injection | ✅ | `javascript-uri` plus `dom-sinks` |
| CSS Injection | 🔶 | `css-injection` blocks `<style>`/`</style>` breakout (query/body/headers), `expression()`/`-moz-binding:`/`url(javascript:)` (headers included), remote `@import` and `url(//...)` loads, and the attribute-selector `[...^=...]{...url(...)}` exfiltration shape. `behavior:`/`binding:` stay unmatched (plain-text collisions; dead targets), and context-aware sanitization plus same-origin exfiltration remain application-side. Sites with user-authored CSS need an override |
| Open Redirect | 🔶 | `open-redirect.redirect-parameter-url` blocks absolute and protocol-relative targets on the common parameter names (`redirect[_to|_url|_path]`, `next`, `return_to`, `continue`, `goto`, `dest[ination]`, `target_url`, `out_url`); custom parameter names and same-site absolute redirects stay indistinguishable, `redirect_uri`/payment return URLs are intentionally excluded, and response-phase rules can inspect the `Location` header for defense in depth |
| Clickjacking | ❌ | No detection. Mitigation is possible via `response_headers.set` (`X-Frame-Options`/CSP), i.e. header policy rather than detection |

## 3. Path and File Operations

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Path Traversal / Directory Traversal | ✅ | `path-traversal` plus `path-normalization`; raw and percent-decoded (2 passes) plus normalized path forms all match. The lab-only CVE-2021-41773 fixture confirms the direct `.%2e` traversal canary extraction is blocked by the decoded path rule |
| Local File Inclusion (LFI) | ✅ | Same rules plus `php-wrappers` (`php://filter|input|data`, `expect/zip/phar://`) |
| Remote File Inclusion (RFI) | ✅ | `remote-file-inclusion`: include-style parameters (`include`, `require`, `page`, `template`, `file`, `module`, `load`, ...) pointing at remote schemes (http/ftp/sftp/tftp/smb/nfs/gopher/dict), protocol-relative `//`, or UNC `\\` hosts; per-host allowlisting is not expressible |
| Malicious File Upload | 🔶 | Extension-based blocking (php/phtml/jsp/asp/exe/war, ...) plus `limits.upload_inspection` (default `mismatch`), which rejects an executable header or active markup at the leading position and server-side script markers (`<?php`, `<?=`, `<%`) anywhere in the inspected part. Padding cannot hide a script polyglot behind an image/PDF/office/media/font claim. Archive contents, executable/markup bytes beyond the leading position, and parts outside the inspected prefix under `body_inspection: stream` remain uninspected |
| Web Shell Upload | 🔶 | Same as above plus CVE-specific signatures (`jspws`, shared DAV paths); the upload check scans the whole inspected part for server-side script markers, so a `GIF89a` + padding + `<?php` polyglot is rejected at any offset. Archive contents, active markup/executable bytes beyond the leading position, and parts outside the inspected prefix remain uninspected |
| Double Extension | ✅ | The extension regex also matches `shell.php.jpg` (`\b` boundary) |
| MIME Type Spoofing | ✅ | `limits.upload_inspection` (default `mismatch`) checks every multipart file part against its declared type or safe filename extension and rejects executable, server-side script, or HTML/XML/SVG content with `403` before rule evaluation; `strict` also covers generic `application/octet-stream` claims, `off` disables the check, and an upload over `max_body_bytes` is prefix-only under `body_inspection: stream` |
| Null Byte Injection | ✅ | `protocol-anomalies.null-byte` (`%00`) |
| Arbitrary File Reference / Download | 🔶 | Traversal and `sensitive-files` block known shapes; IDOR-style download abuse is undetectable in principle |

## 4. HTTP Protocol Abuse

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| HTTP Request Smuggling | 🔶 | hyper's strict framing (rejects TE/CL conflicts and malformed chunked bodies), `embedded-http-request-in-body`, CVE signatures, black-box probes. No generic TE/CL semantics rule |
| HTTP Request Splitting | 🔶 | `crlf-injection` plus embedded-HTTP inspection |
| HTTP Response Splitting | 🔶 | Same (CRLF in headers is blocked) |
| HTTP Parameter Pollution (HPP) | ❌ | Duplicate-parameter inspection/normalization is absent |
| Host Header Injection | 🔶 | Full enforcement when `allowed_hosts` is configured: a missing, malformed, duplicate, or unlisted Host (HTTP/1.1) or `:authority` (HTTP/2 / HTTP/3) is rejected with `400`/`421` before body buffering and rule evaluation, and `ALLOW` rules cannot bypass it. Fresh `kunato init --acme-domain` installs seed the list and accept `--allowed-host`; manual certificate/TLS-proxy installs and existing configs opt in, and an unset list leaves the previous behavior. A client-supplied `X-Forwarded-Host` is replaced with the Host header. `malformed-host-header` and `oversized-host-header` remain as defense in depth when the policy is unset (the Rack/Forwarded allowlist CVEs are CVSS 4.8, below the bundling bar) |
| Invalid Content-Length / Transfer-Encoding | 🔶 | Kunato's request-head checks reject duplicate Host, duplicate Content-Length, CL+TE, and non-chunked Transfer-Encoding before forwarding; the lab's per-framing direct controls show no smuggled request reaches the origin. CVE-specific rules add defense in depth; no generic TE/CL semantics rule |
| HTTP Method Abuse | ✅ | `bad-methods` (TRACE/TRACK/CONNECT/DEBUG) plus WebDAV methods (LOCK/COPY/MOVE/PROPPATCH); method conditions match the wire method — Rack-style `_method` overrides are not resolved, but Rack only accepts standard methods, so `bad-methods` cannot be bypassed. Non-canonical case variants of standard methods (`get`, `pOsT`) are rejected with `400` before rule evaluation, closing the method-case authorization-bypass class (OpenNMS CVE-2026-111235) |
| Abnormal HTTP Headers | 🔶 | `protocol-anomalies` plus CVE-specific (invalid Priority, oversized Range, ...); generic cases need rules |
| Oversized Header / Request | ✅ | Headers over 32 KiB or 100 fields get 431, paths over 8 KiB get 414. Head limits are enforced before body ingestion and inspection-memory reservation on HTTP/1.1, HTTP/2, HTTP/3, and WebSocket handshakes, including when a declared body never arrives. Request bodies over `max_body_bytes` (8 MiB default) are evaluated on the inspected prefix when body-targeting rules, a GraphQL endpoint, or multipart upload inspection need it; a matching ALLOW forwards, a matching BLOCK uses its response, and if neither decides the body gets 413. The decision uses the bytes actually read, so chunked and HTTP/2 / HTTP/3 bodies are covered. `limits.body_inspection: stream` is the documented opt-out for applications that need larger uploads; it inspects only the prefix and logs a warning when the configuration loads |
| HTTP/2 Rapid Reset and similar layer DoS | 🔶 | Mitigated by `max_concurrent_streams`, ping timeouts, and connection caps; no dedicated signature (framing cannot be expressed in the black-box list either). Rust proxy tests replay Rapid Reset, a CONTINUATION flood, and an oversized HPACK header block while a normal HTTP/2 request still succeeds; the lab `h2` suite adds the same variants over TLS with a fresh normal connection after each attack |
| Slow HTTP / Connection Exhaustion | 🔶 | The sandbox `slow` suite holds 8 partial-header connections for 2 seconds and the independent normal client stays 200 while Kunato stays within 256 MiB/64 pids. The `availability` suite adds a slow-body `408`, a slow-read probe, per-source and global connection caps with `503`, and an upstream-response timeout with `504`; the `connect` suite adds a slow upstream connect with `502`; the `restart` suite adds SIGTERM under load with recovery. Header/body read timeouts and connection caps bound the impact; no dedicated slow-request signature |
| Sustained Load / Throughput | 🔶 | The sandbox `load` suite runs 50 requests/second for 60 seconds with p95/p99, success, RSS, restarts, immediate recovery, and metrics checks (p95 48.1 ms, p99 48.4 ms, 100% success, no block/rate-limit/overload/upstream-timeout movement). Fixed-runner trend, not a capacity claim |
| HTTP Desync | 🔶 | Same handling as smuggling |
| WebSocket Application Payload | 🔶 | Client-to-server text and binary messages are reassembled up to `limits.websocket_message_bytes` (1 MiB default) and matched against body-target rules; a violating tunnel closes with code 1008. WebSocket extensions are not negotiated, so frames stay uncompressed. Rules with per-rule limits are skipped, binary payloads are matched lossily, and server-to-client frames are not inspected |

Protocol compatibility: before HTTP/1.1 forwarding, split request `Cookie`
fields are joined with `; ` in field order without decoding their bytes
(RFC 9113, section 8.2.3). This covers HTTP/2, HTTP/3, and HTTP/1.1 WebSocket
handshakes and prevents upstream parsers from comma-joining or dropping session
cookies. Rule evaluation retains the original fields, and response `Set-Cookie`
fields remain separate. Proxy regression tests cover both directions. This is
a forwarding correction, not a new cookie-tampering detection mechanism; the
attack verdicts below are unchanged.

Proxy resource and compatibility guards: the 256 MiB inspection budget remains
reserved while request contexts wait on the upstream and while buffered bytes
are retained in replayed request/response frames, clones, or slices. Capacity
pressure returns `503`; a slow upstream cannot detach retained prefixes from the
budget. Status/header-only response rules do not buffer bodies, preserving
streaming behavior. WebSocket handshakes strip all Connection-nominated fields
in both directions before rebuilding upgrade headers, and HTTP/3 HEAD responses
suppress content for rule blocks and generated errors. Unit and proxy regression
tests exercise these paths without adding attack signatures or changing verdicts.

## 5. API Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| REST API Injection | ✅ | Generic injection rules inspect query/body/cookies with Content-Type-aware decoding |
| GraphQL Injection / Abuse | 🔶 | One CVE-specific case (SSRF mutation, caught by metadata rules) |
| GraphQL Introspection Abuse | 🔶 | `api-discovery.graphql-introspection` LOGs `__schema` and `__type(...)` in query/body; raise the category to BLOCK to disable introspection. The harness cannot assert LOG behavior; `allowed.txt` pins that `__typename` queries and the logged paths stay forwarded |
| GraphQL Query Depth / Complexity | ✅ | `limits.graphql` expands fragments and caps both selection depth (default 20) and expanded field count (default 1000) on recognized GraphQL paths; over-limit documents get `400`, and a body larger than `max_body_bytes` gets `413` rather than being forwarded with an uninspected remainder. Cycles and duplicate fragment definitions are rejected, and the parser has a bounded node budget. Verified by unit and proxy tests and `blocked.txt` (deep, fragment-chain, fragment-amplification, and alias-flood shapes). The HTTP transports are covered; GraphQL operations carried in WebSocket frames after a `101` handshake remain opaque |
| API Parameter Tampering | ❌ | Business-logic dependent |
| Mass Assignment | ❌ | Business-logic dependent |
| Excessive Data Exposure Requests | 🔶 | Response-phase inspection can express it, but no bundled rules (only private keys, SQL errors, ...) |
| API Endpoint Enumeration | 🔶 | Scanner UA blocking, rate limits, and behavioral `404`/distinct-path flags (LOG default; `enumeration.action: BLOCK` opt-in) |
| API Version Abuse | ❌ | No rules |
| Content-Type Spoofing | ❌ | No rules |
| JSON/XML Payload Tampering | 🔶 | JSON escapes, multipart, and form-urlencoded bodies are decoded for inspection; detection depends on signatures |
| Schema Validation Violations | ❌ | No schema validation feature |
| API Rate Limit Evasion | ✅ | Limits key on the resolved client IP: direct peer by default, or a bounded assertion from explicitly configured `client_ip.trusted_proxies`. XFF is walked right to left through trusted hops; malformed/missing assertions from trusted peers get `400`. Untrusted peers cannot change identity with headers. IPv6 is aggregated by prefix (default /64), preventing rotation within that prefix from obtaining fresh budgets. Shared-IP users remain grouped |

## 6. Authentication and Login Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Brute Force | 🔶 | `login-throttle.login-attempts` bundles a per-source `limit` (10 requests/60s) over the common login paths (`wp-login.php`, `xmlrpc.php`, `users/sign_in`, `admin/login`, `login`, `logon`, `signin`, `sign_in`, `sign-in`, `session`); transparent within budget, then BLOCK plus ban escalation. Protection also flags per-source `401`/`403` bursts on authentication paths (`protection.behavior.auth`, LOG default, per-signal `BLOCK` opt-in) and logs global bursts for distributed attempts. The limit's firing is covered by unit tests, not `blocked.txt` (the harness runs with protection disabled and sends each request once) |
| Password Spraying | 🔶 | Same throttle, bans, and per-source auth-failure flags slow a single source; the global auth-failure window (LOG only) records spraying spread across many source IPs, but automatic global mitigation is future work |
| Credential Stuffing | 🔶 | Same as brute force; the global auth-failure window records credential lists rotated across many source IPs (LOG only), but cannot identify individual stolen credentials and does not mitigate globally |
| Account / Login Enumeration | ❌ | Not covered (response-phase error-text rules could be added locally) |
| MFA Flooding | 🔶 | Rate limits only |
| OTP Brute Force | 🔶 | Rate limits only |
| Session ID Anomalies | ❌ | No rules |
| Cookie Tampering | 🔶 | Only specific CVE shapes (forged `STATE_COOKIE`, rememberMe `rO0`, ...) |
| JWT Tampering | 🔶 | The `jwt` category blocks unsecured (`alg:none`) and signature-less tokens, `kid`/`jku`/`jwk`/`x5u`/`x5c` key-lookup injection, and the zero-signature CVE-2022-21449 PoCs, across headers/cookies/query/body; claim tampering and re-signing with an unknown weak secret remain undetectable |
| JWT Algorithm Confusion | 🔶 | The `none`-algorithm subset is blocked by `jwt.none-algorithm`; RS256↔HS256 confusion has no static shape (still patch-side watch work in `blackbox/requests/blocked.txt`) |

## 7. Authorization and Access Control

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| IDOR / BOLA | ❌ | Undetectable in principle at the WAF layer |
| Forced Browsing | 🔶 | `sensitive-files` (BLOCK/404) plus `admin-interfaces` (LOG by default) |
| URL Manipulation | 🔶 | Path normalization, matrix parameters, and encoded separators are blocked; general parameter tampering is not |
| Parameter Tampering | ❌ | Business-logic dependent |
| Privilege-Escalation Requests | ❌ | No generic rule (many CVE-specific auth-bypass signatures exist) |
| Admin Interface Access Attempts | 🔶 | `admin-interfaces` logs by default (BLOCK is the documented hardening) plus CVE-specific admin paths (AEM, h2-console, ...) and the Rails dashboards (`sidekiq`, `pghero`, `flipper`, `blazer`, `delayed_job`, `good_job`) |
| Hidden Endpoints / Non-Public APIs | ❌ | No rules |

## 8. Server-Side Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| SSRF | ✅ | `ssrf`: metadata endpoints, loopback (127/8, `localhost`, `[::1]`, `[::]`), RFC1918 ranges, link-local, CGNAT, decimal/hex/octal loopback forms, IPv6 ULA/link-local/mapped forms, protocol-relative values, non-HTTP schemes, and `file://`; DNS names that resolve internally remain outside static reach |
| XXE | ✅ | `xxe` (DOCTYPE plus ENTITY) and CVE-specific rules |
| Unsafe Deserialization | 🔶 | Dense CVE-specific signatures (`rO0AB`, WDDX, ObjectStateFormatter, XStream, OFBiz, ...); `ruby-deserialization` adds generic Marshal (`BAh7`, encoded raw `%04%08`) and YAML `!ruby/` shapes for Ruby/Rails; other runtimes remain CVE-specific |
| RCE Payloads | ✅ | `command-injection` plus JNDI/OGNL/EL known-exploits plus the CVE set |
| Prototype Pollution | 🔶 | CVE-specific only (Kibana Timelion, React RSC `__proto__:then`) |
| Object Injection | 🔶 | CVE-specific (Joomla, Yii, CraftCMS, ...) |
| Log4Shell / JNDI Injection | ✅ | `known-exploits.log4shell` plus nested lookups (`${${...}}`) and `javax.naming.InitialContext` |
| Metadata-Service SSRF | ✅ | `ssrf.metadata-endpoints` |
| Internal Network Discovery | 🔶 | Loopback and metadata endpoints are blocked; arbitrary internal IPs are not (rate limits still apply) |

## 9. CMS and Framework Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| WordPress Exploits | 🔶 | CVE rules plus WP paths (wp-config, author enumeration, xmlrpc logged, and `wp-login.php` / `xmlrpc.php` under `login-throttle`). Plugin CVEs are out of scope by policy |
| Joomla / Drupal and other CMS | ✅ | Many CVE-specific signatures |
| Apache / nginx / IIS Exploits | ✅ | Same (nginx capture overflow, Range abuse, many httpd CVEs) |
| PHP / Laravel Exploits | 🔶 | `laravel-debug-endpoints` (`/telescope`, `/_debugbar`), Composer file discovery, generic PHP object-injection shapes, and Horizon LOGging; Laravel/Symfony CVE signatures remain thin, and WordPress plugin CVEs are out of scope by policy (details below); PHP engine memory-corruption shapes are covered in the php2shell subsection below |
| Java / .NET Exploits | ✅ | Struts/Spring/Log4j and the framework CVE signatures, plus the Spring Actuator sensitive-path rules and generic Java deserialization shapes |
| Vite / Nuxt Frontend Exposure | ✅ | `vite-dev-endpoints` blocks `/@fs/`, `/@vite/`, `/@id/`, `/__vite_ping`, and `/__nuxt_devtools__`; production `/_nuxt` assets and `@user` profile paths are pinned as allowed |
| AI / LLM Service Exposure | 🔶 | `ai-service-management` blocks Ollama model management and Jupyter kernel/terminal endpoints; Gradio/Flowise/vLLM CVEs have no stable request shapes, while pickle, traversal, and SSRF classes are covered generically |
| Node.js / Next.js Exploits | 🔶 | Next.js CVE signatures (middleware subrequest, image optimizer SSRF, RSC route variants, route-match headers), `nextjs-dev-endpoints`, and `prototype-pollution`; the npm ecosystem is watched daily and bundled only when a request shape exists (details below) |
| Django / Python Framework Exploits | 🔶 | `django-debug-endpoints`, `settings.py` discovery, `python-deserialization`, and the Django DEBUG page rule; Django CVEs stay application-side (details below) |
| Struts / Spring | ✅ | S2-xxx, Spring4Shell, and the framework CVE signatures |
| Rails / Laravel | 🔶 | Rails: CVE-2019-5418 (`Accept` traversal), `rails-debug-endpoints` (dev-only `/rails/info`, `/rails/mailers`, `/rails/conductor`, `/letter_opener`), config/log/storage discovery, generic Ruby deserialization, and the bundled Rack multipart DoS shapes (CVE-2026-34827/34829); other 2025-2026 component CVEs (Active Storage, Rack::Static, Puma, Action View) are not virtual-patchable or not yet bundled. Laravel: only `laravel-ignition-endpoint` |
| CVE-Based Virtual Patching | ✅ | Core feature: `cve-2010` ... `cve-2026` categories plus the daily `rules_update` (SHA256 verification, atomic swap) |
| Admin / Debug Endpoint Discovery | 🔶 | `admin-interfaces` (LOG) including the Rails dashboards and Laravel Horizon, the per-stack dev-endpoint categories (Rails, Django, Next.js, Laravel, Vite) in BLOCK, plus CVE-specific debug paths (AEM console, actuator, ...) |

### Ruby on Rails coverage

Rails-specific attack surface beyond the CVE categories above; the rules live in
`rails-debug-endpoints`, `ruby-deserialization`, `cve-2026-04-signatures`, the
`sensitive-files` extensions, and the Rails additions to `admin-interfaces`.

| Area | Status | Evidence / notes |
| --- | --- | --- |
| Rails CVE virtual patching | 🔶 | CVE-2019-5418 (`Accept` traversal) and the Rack multipart DoS shapes (CVE-2026-34827/34829) are bundled; other 2025-2026 component advisories are below the CVSS bar, have no stable request shape, or are patch-side (left-out comments in `blocked.txt`) |
| Dev-only endpoints | ✅ | `rails-debug-endpoints` BLOCKs `/rails/info`, `/rails/mailers`, `/rails/conductor`, and `/letter_opener` |
| Ops dashboards | 🔶 | `admin-interfaces` LOGs `/sidekiq`, `/pghero`, `/flipper`, `/blazer`, `/delayed_job`, `/good_job`; raise to BLOCK once admin addresses are allowlisted |
| Secrets, config, logs, storage | ✅ | `sensitive-files` 404s `master.key`, `credentials/` keys, `database.yml`, `storage.yml`, `/log/*.log`, and the `/storage/` root |
| Ruby deserialization | ✅ | `ruby-deserialization` covers base64 Marshal (`BAh7`), encoded raw `%04%08`, and YAML `!ruby/` tags across query/body/cookies; signed wrappers (`signed_id`, GlobalID, `MessageVerifier`) are not statically detectable |
| Multipart boundary differentials | ✅ | The engine flattens every declared boundary (up to four) and falls back to raw percent passes beyond that, closing the CVE-2026-26961 WAF-bypass class |
| `_method` overrides | 🔶 | Method conditions match the wire method; Rack accepts only standard overrides, so `bad-methods` cannot be bypassed |
| Host / X-Forwarded-Host | 🔶 | When `allowed_hosts` is configured, a client-supplied `X-Forwarded-Host` is replaced with the Host header and unlisted Host / `:authority` names are rejected with `421` before rule evaluation. Fresh ACME installs seed the list from `--acme-domain`; manual installs opt in, and an unset list keeps the previous behavior |
| Patch-side only | ❌ | Active Storage libvips variants (CVE-2026-66066) and Rack::Static prefix exposure (CVE-2026-34785) have no stable request shape — upgrade the gems |
| Application-side | ❌ | CSRF, strong parameters/mass assignment, authorization, and `secret_key_base` exposure cannot be fixed by the WAF |

Functional Rails routes (`/rails/active_storage/*`, `/rails/action_mailbox/*`,
`/cable`) are deliberately passed through and pinned by the near-miss guards in
`allowed.txt`; Active Storage signed URLs are JSON-then-base64 wrappers and do
not match the Marshal signatures.

### Django, Next.js, and Node.js coverage

| Area | Status | Evidence / notes |
| --- | --- | --- |
| Django debug exposure | ✅ | `django-debug-endpoints` BLOCKs `/__debug__/` (debug toolbar); `settings.py` and `local_settings.py` probes are 404ed through `sensitive-files` |
| Django DEBUG pages | ✅ | `response-leaks.django-debug-page` BLOCKs the technical 404/500 page that dumps settings, `SECRET_KEY`, SQL, and source; response rules are outside the black-box harness and have no request-line tests |
| Django CVE shapes | 🔶 | No stable request signatures: CVE-2026-15307 (GeoDjango GDAL file writes/SSRF, 8.8) needs a crafted raster upload, and the cache/validator advisories are below the bar or application-side |
| Python deserialization | ✅ | `python-deserialization` covers base64 pickle (`gAJ`/`gAS`/`gAR` prefixes), encoded raw `%80%0[24]`, and YAML `!!python/` tags |
| Next.js dev exposure | ✅ | `nextjs-dev-endpoints` BLOCKs `/__nextjs*` and `/_next/webpack-hmr`; `/_next/static`, `/_next/data`, and `/_next/image` stay pinned as allowed guards |
| Next.js CVE shapes | 🔶 | Middleware subrequest (CVE-2025-29927), image optimizer SSRF (CVE-2024-34351), RSC variants, and route-match cache poisoning are bundled; preview/draft-mode abuse is indistinguishable from legitimate preview traffic |
| Prototype pollution | ✅ | `prototype-pollution.pollution-paths` blocks `__proto__` and constructor-prototype paths in query, body, and cookies; runtime-to-RCE gadget chains stay application-side |
| npm ecosystem | 🔶 | Daily sources reduce the blind spot (Node.js releases, npm advisories); individual npm CVEs are bundled only when a stable request shape exists |
| Node.js runtime classes | ❌ | llhttp/HTTP smuggling and permission-model issues are protocol or engine concerns, not URL signatures |

### PHP, Java, frontend, and AI service coverage

| Area | Status | Evidence / notes |
| --- | --- | --- |
| Laravel debug exposure | ✅ | `laravel-debug-endpoints` BLOCKs `/telescope` and `/_debugbar`; the Horizon dashboard stays in `admin-interfaces` (LOG) |
| Composer and lockfile discovery | ✅ | `sensitive-files` 404s `composer.json` and `composer.lock` |
| PHP object injection | ✅ | `php-deserialization` blocks serialized `O:`/`C:` object values across cookies, query, and body |
| Spring Actuator | ✅ | `spring-actuator` BLOCKs the secret- and state-dumping endpoints (`env`, `heapdump`, `mappings`, `jolokia`, `shutdown`, ...); `health` and `info` stay pinned as allowed |
| Java deserialization | ✅ | `java-deserialization` covers base64 `rO0AB` and the encoded stream header `%AC%ED%00%05`; raw bytes are unmatched by design |
| Vite / Nuxt dev exposure | ✅ | `vite-dev-endpoints` BLOCKs the Vite internals and Nuxt devtools; production assets stay open |
| AI / notebook service management | 🔶 | `ai-service-management` BLOCKs the Ollama model-management and Jupyter kernel/terminal endpoints; deployments that drive them through Kunato need an override |
| AI/LLM CVE shapes | 🔶 | Gradio (FileExplorer traversal, `proxy_url` SSRF), vLLM, and Flowise (sandbox escapes, OAuth token leaks) advisories have no stable request signatures; generic pickle, traversal, and SSRF layers apply |
| PHP and Maven ecosystems | 🔶 | Packagist, FriendsOfPHP, and the `composer`/`maven` advisories are refreshed daily; individual CVEs are bundled only with a stable request shape |

### PHP engine memory corruption (php2shell)

CVE-2026-109618 interrupts partially initialized PHP state on OOM; cleanup can
consume that state in the same request. CVE-2026-109619 retains request-owned
state across worker requests and can be triggered by non-OOM fatal errors and
initialization diagnostics too. FPM is not generally immune. The request shapes
live in `cve-2026-10-signatures`, with origin-facing form limits in `limits.form`,
optional scoped PHP controls in `php`, and disclosure heuristics in `response-leaks`.

| Area | Status | Evidence / notes |
| --- | --- | --- |
| OOM amplifier (multipart empty uploads) | 🔶 | `php2shell-nested-empty-upload` handles quoted, single-quoted, unquoted, reordered, spaced, empty-index, long-index, and padded metadata; decoded empty-upload metadata also has a canonical inspection form. The 32-part signature and default structural limits cap count, nesting, empty uploads, names, and cumulative work. These are heuristics, not a PHP allocator model |
| Multipart resource amplification | ✅ | Default `limits.form` enforces part/header count, per-part header bytes, field/filename bytes, nesting, field/empty-file count, and cumulative metadata complexity before ALLOW and forwarding. Malformed/ambiguous inputs are rejected. URL-encoded forms receive field-count/name/nesting checks too; unit and integration tests cover exact limits and benign forms |
| `post_max_size` bypass (lengthless / chunked / compressed) | 🔶 | Enabled form limits require complete actual decoded bodies on every transport, including stream mode and ALLOW; decoded oversize or incomplete forms get 413. Chunked multipart also has a bundled signature. HTTP/2/HTTP/3, gzip, and chunked integration tests pin the size/structure policy, but input limits cannot bound arbitrary application allocations and can be explicitly disabled |
| Upload-progress stale-state consumption | 🔶 | The opt-in `php` profile blocks parsed configured progress field names, even without a file, or all multipart when unused. It is scoped by actual hosts/path prefixes and not enabled globally because upload progress can be legitimate. Custom names and positive/negative scopes have regression tests |
| Worker-memory disclosure via session cookies | 🔶 | Bundled `php2shell-session-cookie-leak` blocks PHPSESSID values of 400 or more characters; `php2shell-session-cookie-control-bytes` detects short encoded-control leaks in multipart transactions. The opt-in PHP profile validates configured cookie names, decoded length and character pattern before body buffering/response ALLOW, even without response rules. Integration tests preserve Rails cookies and prevent leaking rejected headers; smaller or alternate-channel disclosures remain possible |
| RCE after the stale-state step | ❌ | The corruption happens inside the PHP process after the fatal; a WAF cannot see the heap, so patching PHP is the only complete fix |

The 2026-10-22 structural/signature regression adds 14 blocked shapes and six
benign guards. Full-corpus forwarding misses fell from 14 to 0; false blocks
remained 0, and final upstream accesses equaled all 454 allowed requests. Existing
malformed-framing probes retain protocol rejections (one intentionally stalled
framing probe times out without reaching the upstream). Response/profile paths
are integration-tested rather than claimed as request-corpus coverage.

## 10. Reconnaissance

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Vulnerability Scanner | ✅ | 20+ tools blocked by User-Agent (sqlmap, nikto, nmap, nuclei, Acunetix, ...) |
| Directory / File / Endpoint Enumeration | 🔶 | Scanner UA, `limit`, rate limits, and behavioral `404`/distinct-path flags (LOG default; `enumeration.action: BLOCK` opt-in); a slow prober below every threshold still passes |
| Backup File Discovery | ✅ | `sensitive-files.backup-and-dump-files` (`.bak/.old/.sql/.swp`, ...) |
| `.git` / `.env` / Config File Discovery | ✅ | `sensitive-files.credentials-and-config` (hidden behind a 404), now including Rails `master.key`, `database.yml`, `storage.yml`, and `credentials/` keys, plus `log-files` (`/log/*.log`) and `active-storage-root` (`/storage/`) |
| phpinfo-style Information Endpoints | ✅ | `sensitive-files.phpinfo-endpoints` 404s `/phpinfo`, `/phpinfo.php`, `/php_info.php`, `/phpversion.php`, and `/.phpinfo.php`; generic `info.php`/`test.php` names are intentionally left alone to avoid breaking application files |
| Swagger/OpenAPI Endpoint Discovery | 🔶 | `api-discovery.swagger-endpoints` LOGs the conventional routes (`/swagger*`, `/swagger-resources`, `/v2|v3/api-docs`, `/api-docs`, `/openapi.json|yaml`); raise the category to BLOCK when the docs are not public. The harness pins that these paths stay forwarded (LOG is not assertable there) |
| Admin Page Discovery | 🔶 | `admin-interfaces` logs by default |
| Error Message Collection | 🔶 | `response-leaks` (stack traces, SQL errors, Server version) plus `response_headers.remove`; mostly LOG by default |
| CMS/Framework Fingerprinting | 🔶 | Server header hiding only |

## 11. Bot and Automation

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Malicious Bot | 🔶 | User-Agent signatures plus behavioral probing and authentication-abuse flags (LOG default; per-signal `BLOCK` opt-in). No JS challenge, and `200`-only scraping is not detected |
| Scraping / Crawling Abuse | 🔶 | SEO/AI crawlers are logged; rate limits slow the rest |
| Account Creation Bots / Login Bots | 🔶 | Rate limits and bans only |
| Inventory Hoarding / Ticket Scalping | ❌ | Not covered |
| Coupon Abuse / Carding / Card Cracking | ❌ | Not covered (business logic) |
| Fake Account Creation / Content and Comment Spam | ❌ | No content rules (rate limits only) |

## 12. DoS and Resource Exhaustion

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| HTTP / GET / POST Flood | ✅ | Per-IP token bucket (429), global RPS and connection budget (503), automatic ban |
| Slow HTTP / Slowloris / Slow POST | ✅ | `header_read` 10s and `body_read` 30s timeouts, a 32-connection per-IP cap, an HTTP/2 first-request deadline, and a `connection_idle` watchdog for connections with no request in flight |
| Large POST Bodies | ✅ | Bodies over `max_body_bytes` (8 MiB default) are evaluated on the inspected prefix when body rules, a GraphQL endpoint, or upload inspection need it; a matching ALLOW forwards, a matching BLOCK uses its response, and if neither decides the body is rejected with 413. Padding past the limit therefore cannot hide a signature from the rules that are evaluated, and the limit is counted from the bytes actually read (chunked and HTTP/2 / HTTP/3 included). `limits.body_inspection: stream` restores prefix-only streaming for larger uploads, and encoded bodies that cannot be fully decoded are still rejected. Rate/connection caps remain the outer bound |
| ReDoS Payloads | ✅ (immunity) | Rust `regex` is linear-time (no backtracking) and load-time guards reject pathological patterns, so ReDoS cannot be induced; no detection needed |
| High-Cost Search Floods | 🔶 | Rate and global limits are charged by inspected body size (one token per 256 KiB); regex scanning stays linear but is not otherwise capped |
| GraphQL Complexity DoS | ✅ | `limits.graphql` rejects documents over the depth or expanded-field limit and rejects any GraphQL body larger than `max_body_bytes` (`413`) instead of forwarding an uninspected remainder; fragment cycles and expansion bombs are rejected, so a single request cannot force unbounded selection processing. Rate limits remain the outer bound for request volume. A GraphQL endpoint driven over a WebSocket tunnel is not covered, because tunnel frames are not inspected |
| API Resource Exhaustion | 🔶 | Rate limits and connection caps |

## 13. Evasion and WAF Bypass

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| URL Encoding / Double URL Encoding | ✅ | Raw plus up to two percent-decode passes are matched uniformly |
| Unicode Encoding | 🔶 | JSON `\u0075` is decoded, but no Unicode normalization (documented in `docs/development.md`) |
| Overlong UTF-8 | 🔶 | No normalization; specific byte patterns (e.g. `%c0%af`) are caught by raw patterns only |
| Case Variation | ✅ | Main rules use `(?i)` |
| Comment Insertion | ✅ | SQL keyword adjacency tolerates whitespace and `/*...*/`, `--`, and `#` comments (UNION/SELECT, ALL/DISTINCT, and time-based function/parenthesis); the local lab added the padded-comment regression |
| Null Byte | ✅ | `%00` blocked |
| Payload / Parameter Fragmentation | 🔶 | Embedded-HTTP inspection and multipart flattening exist; general fragmentation is unhandled |
| Alternative Content-Type | 🔶 | Content-Type-aware decoding plus percent passes for unknown types; evasion itself is not detected |
| Content-Encoding Compression | ✅ | gzip (all members), deflate, br, and zstd bodies are decompressed for inspection, stacked up to three layers. When a body rule exists, a body that cannot be fully decoded within the limit is rejected (413 over-limit, 415 unsupported, 400 malformed) instead of being forwarded uninspected |
| Chunked Encoding Abuse | 🔶 | Rejected at the protocol layer (hyper) |
| Multipart Boundary Abuse | ✅ | every declared boundary is checked (up to four, closing the CVE-2026-26961 parser-differential class); default `limits.form` enforces real 64-part/1 KiB name and per-part header/complexity limits and rejects malformed or ambiguous metadata instead of silently falling back. The part-flood/Rack DoS signatures and expanded `php2shell-nested-empty-upload` complement this structural policy; disabling it explicitly leaves only bounded prefix/signature inspection |
| JSON/XML Structure Evasion | 🔶 | JSON escapes are decoded; no dedicated structural detection |
| Obfuscated JavaScript / SQL | ✅ | Whitespace- and comment-tolerant regexes |
| WAF Fingerprinting | ❌ | Impossible to hide entirely (the block behavior is itself a signature) |
| Rule Bypass Payloads | ❌ | Cannot be guaranteed; the black-box suite is the ongoing control |
| ALLOW Rule Shadowing | ✅ | Engine-level: `ALLOW` rules are compiled into unanimous matching (every path form, every value of a repeated header/cookie, every form of each `in` target) and their `headers`/`cookies`/`response_headers`/`regex` patterns must be fully anchored as verified from the parsed regex (top-level alternation and escaped anchors are rejected). Body-targeting `ALLOW` rules additionally require a complete body, so a forged duplicate value, an appended marker, or a truncated body cannot shadow a later `BLOCK` |

## Core Priority List Summary

| Core item | Status |
| --- | --- |
| SQLi / XSS / Command Injection | ✅ |
| Path Traversal / LFI / RFI | ✅ |
| SSRF | ✅ |
| XXE / RCE payloads | ✅ |
| Malicious file upload | 🔶 (extension plus declared-type/content check) |
| HTTP Protocol Abuse | 🔶 (mostly protocol-layer strictness) |
| Credential Stuffing / Brute Force | 🔶 (bundled login throttle, per-IP rate limits, bans, per-source auth-failure flags, and a global auth-failure log) |
| Bot | 🔶 (User-Agent signatures plus behavioral probing/auth-failure flags; no JS challenge or 200-only scraping detection) |
| API Abuse | 🔶 (GraphQL depth/complexity is capped; introspection and API-docs discovery are logged; schema and business logic uncovered) |
| Known CVE Exploits | ✅ (daily virtual patching) |
| HTTP Flood | ✅ |

## Local security lab evidence

The 2026-10-24 ffuf sandbox suite confirms the current discovery verdicts on DVWA:
`/.git/config`, `/.env`, `/.svn/entries`, `/.htaccess`, `/.DS_Store`,
`/backup.sql`, `/config.php.bak`, `/phpinfo.php`, and `/wp-config.php` are
blocked without origin receipts, `/admin` is blocked by
`etherpad-admin-bypass`, `/wp-admin/` is logged, and 18 legitimate paths retain
their status and body length. The behavior phase enables
`protection.behavior.enumeration` with `BLOCK`; the enumeration source is banned
(403/429) and the separate normal client stays at 200.

The authenticated ZAP baseline logs in, spiders 193 control and 215 protected
authenticated URLs, and runs the passive scan through the WAF while the normal
client stays healthy. ZAP active scanning is deferred: a scoped plan still
exited at activeScan start with ZAP 2.17.0 (code 2, empty report), and the
pinned image is the latest published stable digest. Active injection controls
therefore remain the sqlmap UNION dump, the Nuclei CVE-2021-41773 canary, and
goTestWAF.

The 2026-10-24 mutation sandbox suite ran 15 reviewed attacks and 10 benign
near-misses: all 15 attacks were blocked with no origin receipt and all 10
benign cases reached the origin unchanged. The transforms covered keyword
case, block comments, newlines, JSON and form bodies, parameter pollution,
alternative XSS tags, dot padding, shell separators, command substitution, and
header values. The pinned OWASP CRS 4.3.0 comparison agreed on all 25 decisions
(`agree-block` 15, `agree-allow` 10); it is an observation, not a gate.

The 2026-10-24 benign and availability suites add five benign workflows and eight
availability checks. The benign cases (JSON API, multipart PDF upload,
percent-encoded Japanese query, 16 KiB body, chunked response) all forwarded
unchanged. The availability cases held a partial body to `408`, survived a
slow read, enforced the per-source connection cap with `503` while the normal
client stayed `200`, and timed out a slow origin with `504`; RSS, restarts, and
the upstream-timeout metric stayed within bounds. The ban suite then triggered a
`429` ban from one source, observed a `200` recovery after the two-second ban,
kept the independent normal client at `200`, and recorded the ban counter. The
WebSocket suite proved PING/PONG, a fragmented text echo, and a close handshake
through the tunnel. The Rust proxy tests add HTTP/2 Rapid Reset,
CONTINUATION-flood, oversized HPACK, a malformed raw HTTP/3 request stream, hot
reload under load, and rules update plus reload under load; normal HTTP/2 and
HTTP/3 requests still succeed afterward.

## Notable Gaps

JWT signature/claim forgery beyond the bundled shapes (algorithm confusion in
either direction, arbitrary re-signing), open redirect via unlisted parameter
names, HPP, deep upload content (content outside the inspected prefix,
archives, nested files, executable or markup bytes beyond the leading
position), `200`-only scraping, distributed mitigation for
credential stuffing, and the business-logic family (IDOR/BOLA, mass assignment,
parameter tampering). CSRF, IDOR, authorization gaps, and session design cannot
be fixed by a WAF at all; Kunato can only assist through custom response-phase
rules. Closing a gap usually means either a YAML rule (most request-shape gaps)
or an engine feature (behavioral and stateful checks).

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) stays Partial: form resource
guards and expanded signatures reduce multipart OOM pressure, the opt-in PHP
profile can disable unused upload progress, and response checks catch some
session-cookie disclosures. Application-dependent allocations, other lifecycle
consumers, alternate disclosure channels, and shared OPcache/heap state remain
below the WAF. Patching PHP is the only complete fix.

Behavioral detection (Phase 1) covers `404` probing, per-source authentication
failure bursts, and a global authentication-failure log. It defaults to `LOG`;
a class becomes `Covered` only when the bundled default stops the attack, not
merely because a signal exists. See
[the behavioral detection notes](behavioral-detection.md).

Trusted-proxy identity resolution now keeps clients behind a CDN/load balancer
separate when `client_ip` is configured. All request protection, source rules,
and upstream canonical XFF use the same resolved IP; connection caps remain
transport-based. Unit and proxy tests cover spoofed prefixes, untrusted peers,
bounded/malformed chains, shared HTTP/2 connections, HTTP/3, WebSocket, and
authentication outcome counts. This closes a deployment limitation without
changing category verdicts or the bundled 492-rule count; behavioral actions
still default to LOG. The snapshot date is 2026-10-25.
