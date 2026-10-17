# Attack Coverage TODO

Status of common WAF attack classes against the bundled set shipped with Kunato
(`rules.example.yaml`, mirrored by `dist/rules.yaml`) and the mechanisms in
`src/` (rule engine, protocol/resource limits, protection). Snapshot date:
2026-10-17; the managed set carried 474 rules then.

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
often means "no signature shipped", not "impossible".

## 1. Injection

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| SQL Injection | ✅ | `sql-injection`: UNION, boolean, stacked, time-based (comment-obfuscation resistant), blind inference, executable comments, metadata functions |
| NoSQL Injection | ✅ | `nosql-injection`: Mongo operators (`$where/$ne/$regex`, ...) |
| OS Command Injection | ✅ | `command-injection`: shell metacharacters plus command words, `$()`/backticks, brace expansion, `/bin/`, `cmd.exe`, `powershell` |
| LDAP Injection | ❌ | Only Log4Shell `jndi:ldap` strings; no generic filter-escape detection |
| XPath Injection | ❌ | No rules |
| XML Injection | 🔶 | XXE (`<!DOCTYPE[`/`<!ENTITY`) is generic and blocked; generic XML structure injection and SOAP deserialization are CVE-specific |
| SSTI | ✅ | `ssti`: generic arithmetic probes and engine gadgets for Jinja/Twig (`{{7*7}}`, dunder access), Freemarker (`<#assign`, `?new()`), Velocity (`$class.inspect`, `#set($`), ERB/JSP (`<%=`), Thymeleaf (`*{}`), and Smarty (`{7*7}`); `${`/`%{` are covered by `cve-2019-signatures.struts-expression-injection`; the CVE-specific set is retained |
| Expression Language Injection | 🔶 | Same: CVE-specific (Ivanti EPMM, Struts OGNL, Nexus JavaEL, ...) |
| CRLF Injection / HTTP Header Injection | ✅ | `protocol-anomalies.crlf-injection` (`%0d%0a` etc. in path/query/headers) |

## 2. XSS and Browser-Side

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Reflected XSS | ✅ | `xss`: script/iframe/object/embed, broad event-handler list, `javascript:`/`vbscript:`, `data:text/html`, DOM sinks |
| Stored XSS | 🔶 | Input-side detection uses the same rules; output-time context escaping is the application's job. `response-leaks` ships no XSS signatures |
| DOM Based XSS | 🔶 | `dom-sinks` (`document.cookie`, `eval(` etc.) exists but the root cause is client-side |
| HTML Injection | 🔶 | script/iframe-like tags are blocked; generic tags (`<div>`) pass |
| JavaScript Injection | ✅ | `javascript-uri` plus `dom-sinks` |
| CSS Injection | 🔶 | `css-injection` blocks `<style>`/`</style>` breakout (query/body/headers), `expression()`/`-moz-binding:`/`url(javascript:)` (headers included), remote `@import` and `url(//...)` loads, and the attribute-selector `[...^=...]{...url(...)}` exfiltration shape. `behavior:`/`binding:` stay unmatched (plain-text collisions; dead targets), and context-aware sanitization plus same-origin exfiltration remain application-side. Sites with user-authored CSS need an override |
| Open Redirect | 🔶 | `open-redirect.redirect-parameter-url` blocks absolute and protocol-relative targets on the common parameter names (`redirect[_to|_url|_path]`, `next`, `return_to`, `continue`, `goto`, `dest[ination]`, `target_url`, `out_url`); custom parameter names and same-site absolute redirects stay indistinguishable, `redirect_uri`/payment return URLs are intentionally excluded, and response-phase rules can inspect the `Location` header for defense in depth |
| Clickjacking | ❌ | No detection. Mitigation is possible via `response_headers.set` (`X-Frame-Options`/CSP), i.e. header policy rather than detection |

## 3. Path and File Operations

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Path Traversal / Directory Traversal | ✅ | `path-traversal` plus `path-normalization`; raw and percent-decoded (2 passes) plus normalized path forms all match |
| Local File Inclusion (LFI) | ✅ | Same rules plus `php-wrappers` (`php://filter|input|data`, `expect/zip/phar://`) |
| Remote File Inclusion (RFI) | ✅ | `remote-file-inclusion`: include-style parameters (`include`, `require`, `page`, `template`, `file`, `module`, `load`, ...) pointing at remote schemes (http/ftp/sftp/tftp/smb/nfs/gopher/dict), protocol-relative `//`, or UNC `\\` hosts; per-host allowlisting is not expressible |
| Malicious File Upload | 🔶 | Extension-based blocking (php/phtml/jsp/asp/exe/war, ...); no MIME, magic-byte, or content inspection |
| Web Shell Upload | 🔶 | Same as above plus CVE-specific signatures (`jspws`, shared DAV paths) |
| Double Extension | ✅ | The extension regex also matches `shell.php.jpg` (`\b` boundary) |
| MIME Type Spoofing | ❌ | No consistency check between Content-Type and payload |
| Null Byte Injection | ✅ | `protocol-anomalies.null-byte` (`%00`) |
| Arbitrary File Reference / Download | 🔶 | Traversal and `sensitive-files` block known shapes; IDOR-style download abuse is undetectable in principle |

## 4. HTTP Protocol Abuse

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| HTTP Request Smuggling | 🔶 | hyper's strict framing (rejects TE/CL conflicts and malformed chunked bodies), `embedded-http-request-in-body`, CVE signatures, black-box probes. No generic TE/CL semantics rule |
| HTTP Request Splitting | 🔶 | `crlf-injection` plus embedded-HTTP inspection |
| HTTP Response Splitting | 🔶 | Same (CRLF in headers is blocked) |
| HTTP Parameter Pollution (HPP) | ❌ | Duplicate-parameter inspection/normalization is absent |
| Host Header Injection | 🔶 | `malformed-host-header` and `oversized-host-header` only; host-rewrite abuse depends on the application. A client-supplied `X-Forwarded-Host` is replaced with the Host header, but an `allowed_hosts` policy is not implemented (the Rack/Forwarded allowlist CVEs are CVSS 4.8, below the bundling bar) |
| Invalid Content-Length / Transfer-Encoding | 🔶 | Rejected at the protocol layer plus CVE-specific rules; no generic rule |
| HTTP Method Abuse | ✅ | `bad-methods` (TRACE/TRACK/CONNECT/DEBUG) plus WebDAV methods (LOCK/COPY/MOVE/PROPPATCH); method conditions match the wire method — Rack-style `_method` overrides are not resolved, but Rack only accepts standard methods, so `bad-methods` cannot be bypassed |
| Abnormal HTTP Headers | 🔶 | `protocol-anomalies` plus CVE-specific (invalid Priority, oversized Range, ...); generic cases need rules |
| Oversized Header / Request | 🔶 | Headers over 32 KiB or 100 fields get 431, paths over 8 KiB get 414. Request bodies are not rejected: only the first 1 MiB is inspected and the rest streams through (an explicit content-length rule is needed to reject) |
| HTTP/2 Rapid Reset and similar layer DoS | 🔶 | Mitigated by `max_concurrent_streams`, ping timeouts, and connection caps; no dedicated signature (framing cannot be expressed in the black-box list either) |
| HTTP Desync | 🔶 | Same handling as smuggling |

## 5. API Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| REST API Injection | ✅ | Generic injection rules inspect query/body/cookies with Content-Type-aware decoding |
| GraphQL Injection / Abuse | 🔶 | One CVE-specific case (SSRF mutation, caught by metadata rules) |
| GraphQL Introspection Abuse | 🔶 | `api-discovery.graphql-introspection` LOGs `__schema` and `__type(...)` in query/body; raise the category to BLOCK to disable introspection. The harness cannot assert LOG behavior; `allowed.txt` pins that `__typename` queries and the logged paths stay forwarded |
| GraphQL Query Depth / Complexity | ❌ | No rules |
| API Parameter Tampering | ❌ | Business-logic dependent |
| Mass Assignment | ❌ | Business-logic dependent |
| Excessive Data Exposure Requests | 🔶 | Response-phase inspection can express it, but no bundled rules (only private keys, SQL errors, ...) |
| API Endpoint Enumeration | 🔶 | Scanner UA blocking plus rate limits only; no behavioral detection |
| API Version Abuse | ❌ | No rules |
| Content-Type Spoofing | ❌ | No rules |
| JSON/XML Payload Tampering | 🔶 | JSON escapes, multipart, and form-urlencoded bodies are decoded for inspection; detection depends on signatures |
| Schema Validation Violations | ❌ | No schema validation feature |
| API Rate Limit Evasion | ✅ | Limits key on the TCP peer IP; client-supplied `X-Forwarded-For` is ignored and IPv6 is aggregated by prefix (default /64), so rotation cannot bypass |

## 6. Authentication and Login Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Brute Force | 🔶 | `login-throttle.login-attempts` bundles a per-source `limit` (10 requests/60s) over the common login paths (`wp-login.php`, `xmlrpc.php`, `users/sign_in`, `admin/login`, `login`, `logon`, `signin`, `sign_in`, `sign-in`, `session`); transparent within budget, then BLOCK plus ban escalation. The limit's firing is covered by unit tests, not `blocked.txt` (the harness runs with protection disabled and sends each request once) |
| Password Spraying | 🔶 | Same throttle and bans slow a single source; spraying spread across many source IPs stays below each budget and passes |
| Credential Stuffing | 🔶 | Same as brute force; credential lists rotated across many source IPs are not detectable |
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
| PHP / Laravel Exploits | 🔶 | `laravel-debug-endpoints` (`/telescope`, `/_debugbar`), Composer file discovery, generic PHP object-injection shapes, and Horizon LOGging; Laravel/Symfony CVE signatures remain thin, and WordPress plugin CVEs are out of scope by policy (details below) |
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
| Host / X-Forwarded-Host | 🔶 | A client-supplied `X-Forwarded-Host` is replaced with the Host header; no `allowed_hosts` policy yet |
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

## 10. Reconnaissance

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Vulnerability Scanner | ✅ | 20+ tools blocked by User-Agent (sqlmap, nikto, nmap, nuclei, Acunetix, ...) |
| Directory / File / Endpoint Enumeration | 🔶 | Scanner UA, `limit`, and rate limits in combination; no behavioral detection of iterative probing |
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
| Malicious Bot | 🔶 | User-Agent signatures only; no behavioral analysis or JS challenge |
| Scraping / Crawling Abuse | 🔶 | SEO/AI crawlers are logged; rate limits slow the rest |
| Account Creation Bots / Login Bots | 🔶 | Rate limits and bans only |
| Inventory Hoarding / Ticket Scalping | ❌ | Not covered |
| Coupon Abuse / Carding / Card Cracking | ❌ | Not covered (business logic) |
| Fake Account Creation / Content and Comment Spam | ❌ | No content rules (rate limits only) |

## 12. DoS and Resource Exhaustion

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| HTTP / GET / POST Flood | ✅ | Per-IP token bucket (429), global RPS and connection budget (503), automatic ban |
| Slow HTTP / Slowloris / Slow POST | ✅ | `header_read` 10s and `body_read` 30s timeouts plus a 32-connection per-IP cap |
| Large POST Bodies | 🔶 | Only the first 1 MiB is inspected and the rest streams through; rate/connection caps and explicit rules (e.g. content-length) are the levers |
| ReDoS Payloads | ✅ (immunity) | Rust `regex` is linear-time (no backtracking) and load-time guards reject pathological patterns, so ReDoS cannot be induced; no detection needed |
| High-Cost Search Floods | 🔶 | Rate limits only |
| GraphQL Complexity DoS | ❌ | Not covered |
| API Resource Exhaustion | 🔶 | Rate limits and connection caps |

## 13. Evasion and WAF Bypass

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| URL Encoding / Double URL Encoding | ✅ | Raw plus up to two percent-decode passes are matched uniformly |
| Unicode Encoding | 🔶 | JSON `\u0075` is decoded, but no Unicode normalization (README documents this) |
| Overlong UTF-8 | 🔶 | No normalization; specific byte patterns (e.g. `%c0%af`) are caught by raw patterns only |
| Case Variation | ✅ | Main rules use `(?i)` |
| Comment Insertion | ✅ | SQL timing rules tolerate comments between function name and parenthesis |
| Null Byte | ✅ | `%00` blocked |
| Payload / Parameter Fragmentation | 🔶 | Embedded-HTTP inspection and multipart flattening exist; general fragmentation is unhandled |
| Alternative Content-Type | 🔶 | Content-Type-aware decoding plus percent passes for unknown types; evasion itself is not detected |
| Content-Encoding Compression | ✅ | gzip (all members), deflate, br, and zstd bodies are decompressed for inspection, stacked up to three layers; zstd frames with a window over 8 MiB fall back to raw |
| Chunked Encoding Abuse | 🔶 | Rejected at the protocol layer (hyper) |
| Multipart Boundary Abuse | ✅ | every declared boundary is flattened for inspection (up to four, closing the CVE-2026-26961 parser-differential class); 64-part and 1 KiB name limits, malformed bodies inspected raw, part-flood rule, and the Rack DoS signatures (escape-heavy part headers, chunked multipart uploads) |
| JSON/XML Structure Evasion | 🔶 | JSON escapes are decoded; no dedicated structural detection |
| Obfuscated JavaScript / SQL | ✅ | Whitespace- and comment-tolerant regexes |
| WAF Fingerprinting | ❌ | Impossible to hide entirely (the block behavior is itself a signature) |
| Rule Bypass Payloads | ❌ | Cannot be guaranteed; the black-box suite is the ongoing control |

## Core Priority List Summary

| Core item | Status |
| --- | --- |
| SQLi / XSS / Command Injection | ✅ |
| Path Traversal / LFI / RFI | ✅ |
| SSRF | ✅ |
| XXE / RCE payloads | ✅ |
| Malicious file upload | 🔶 (extension-based) |
| HTTP Protocol Abuse | 🔶 (mostly protocol-layer strictness) |
| Credential Stuffing / Brute Force | 🔶 (bundled login throttle, per-IP rate limits, and bans) |
| Bot | 🔶 (User-Agent signatures only) |
| API Abuse | ❌ to 🔶 (GraphQL introspection and API-docs discovery are logged; depth/complexity, schema, and business logic uncovered) |
| Known CVE Exploits | ✅ (daily virtual patching) |
| HTTP Flood | ✅ |

## Notable Gaps

JWT signature/claim forgery beyond the bundled shapes (algorithm confusion in
either direction, arbitrary re-signing), GraphQL depth and complexity limits,
LDAP/XPath injection, open redirect via unlisted parameter names, HPP, MIME
spoofing, behavioral bot detection, and the
business-logic family (IDOR/BOLA, mass assignment, parameter tampering). CSRF, IDOR, authorization gaps, and
session design cannot be fixed by a WAF at all; Kunato can only assist through
custom response-phase rules. Closing a gap usually means either a YAML rule
(most request-shape gaps) or an engine feature (behavioral and stateful checks).
