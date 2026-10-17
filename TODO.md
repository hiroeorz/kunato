# Attack Coverage TODO

Status of common WAF attack classes against the bundled set shipped with Kunato
(`rules.example.yaml`, mirrored by `dist/rules.yaml`) and the mechanisms in
`src/` (rule engine, protocol/resource limits, protection). Snapshot date:
2026-10-17; the managed set carried 435 rules then.

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
| SSTI | 🔶 | CVE-specific only (FreeMarker, Velocity, phpcms, WeRSS, ...); no generic `{{7*7}}` style pattern |
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
| CSS Injection | ❌ | No rules |
| Open Redirect | ❌ | No generic rule (customable with a query-URL regex) |
| Clickjacking | ❌ | No detection. Mitigation is possible via `response_headers.set` (`X-Frame-Options`/CSP), i.e. header policy rather than detection |

## 3. Path and File Operations

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Path Traversal / Directory Traversal | ✅ | `path-traversal` plus `path-normalization`; raw and percent-decoded (2 passes) plus normalized path forms all match |
| Local File Inclusion (LFI) | ✅ | Same rules plus `php-wrappers` (`php://filter|input|data`, `expect/zip/phar://`) |
| Remote File Inclusion (RFI) | ❌ | No generic rule (`file://` is blocked by `ssrf`; the rest is CVE-specific) |
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
| Host Header Injection | 🔶 | `malformed-host-header` and `oversized-host-header` only; host-rewrite abuse depends on the application |
| Invalid Content-Length / Transfer-Encoding | 🔶 | Rejected at the protocol layer plus CVE-specific rules; no generic rule |
| HTTP Method Abuse | ✅ | `bad-methods` (TRACE/TRACK/CONNECT/DEBUG) plus WebDAV methods (LOCK/COPY/MOVE/PROPPATCH) |
| Abnormal HTTP Headers | 🔶 | `protocol-anomalies` plus CVE-specific (invalid Priority, oversized Range, ...); generic cases need rules |
| Oversized Header / Request | 🔶 | Headers over 32 KiB or 100 fields get 431, paths over 8 KiB get 414. Request bodies are not rejected: only the first 1 MiB is inspected and the rest streams through (an explicit content-length rule is needed to reject) |
| HTTP/2 Rapid Reset and similar layer DoS | 🔶 | Mitigated by `max_concurrent_streams`, ping timeouts, and connection caps; no dedicated signature (framing cannot be expressed in the black-box list either) |
| HTTP Desync | 🔶 | Same handling as smuggling |

## 5. API Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| REST API Injection | ✅ | Generic injection rules inspect query/body/cookies with Content-Type-aware decoding |
| GraphQL Injection / Abuse | 🔶 | One CVE-specific case (SSRF mutation, caught by metadata rules) |
| GraphQL Introspection Abuse | ❌ | No rules |
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
| Brute Force | 🔶 | Per-IP rate limits plus ban escalation slow it; per-rule `limit: {requests, window}` exists but the bundled set configures no login-specific limit |
| Password Spraying | 🔶 | Same; slow, distributed spraying passes |
| Credential Stuffing | 🔶 | Same as above |
| Account / Login Enumeration | ❌ | Not covered (response-phase error-text rules could be added locally) |
| MFA Flooding | 🔶 | Rate limits only |
| OTP Brute Force | 🔶 | Rate limits only |
| Session ID Anomalies | ❌ | No rules |
| Cookie Tampering | 🔶 | Only specific CVE shapes (forged `STATE_COOKIE`, rememberMe `rO0`, ...) |
| JWT Tampering | 🔶 | CVE-specific (default-secret tokens, ...) only |
| JWT Algorithm Confusion | ❌ | No generic validation (listed as patch-side watch work in `blackbox/requests/blocked.txt`) |

## 7. Authorization and Access Control

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| IDOR / BOLA | ❌ | Undetectable in principle at the WAF layer |
| Forced Browsing | 🔶 | `sensitive-files` (BLOCK/404) plus `admin-interfaces` (LOG by default) |
| URL Manipulation | 🔶 | Path normalization, matrix parameters, and encoded separators are blocked; general parameter tampering is not |
| Parameter Tampering | ❌ | Business-logic dependent |
| Privilege-Escalation Requests | ❌ | No generic rule (many CVE-specific auth-bypass signatures exist) |
| Admin Interface Access Attempts | 🔶 | `admin-interfaces` logs by default (BLOCK is the documented hardening) plus CVE-specific admin paths (AEM, h2-console, ...) |
| Hidden Endpoints / Non-Public APIs | ❌ | No rules |

## 8. Server-Side Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| SSRF | 🔶 | `ssrf`: cloud metadata IPs, 127.0.0.1/localhost/::1, `file://`. Arbitrary internal ranges (10.x, ...) and decimal/hex IP forms are uncovered |
| XXE | ✅ | `xxe` (DOCTYPE plus ENTITY) and CVE-specific rules |
| Unsafe Deserialization | 🔶 | Dense CVE-specific signatures (`rO0AB`, WDDX, ObjectStateFormatter, XStream, OFBiz, ...); no generic rule |
| RCE Payloads | ✅ | `command-injection` plus JNDI/OGNL/EL known-exploits plus the CVE set |
| Prototype Pollution | 🔶 | CVE-specific only (Kibana Timelion, React RSC `__proto__:then`) |
| Object Injection | 🔶 | CVE-specific (Joomla, Yii, CraftCMS, ...) |
| Log4Shell / JNDI Injection | ✅ | `known-exploits.log4shell` plus nested lookups (`${${...}}`) and `javax.naming.InitialContext` |
| Metadata-Service SSRF | ✅ | `ssrf.metadata-endpoints` |
| Internal Network Discovery | 🔶 | Loopback and metadata endpoints are blocked; arbitrary internal IPs are not (rate limits still apply) |

## 9. CMS and Framework Attacks

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| WordPress Exploits | 🔶 | CVE rules plus WP paths (wp-config, author enumeration, xmlrpc logged). Plugin CVEs are out of scope by policy |
| Joomla / Drupal and other CMS | ✅ | Many CVE-specific signatures |
| Apache / nginx / IIS Exploits | ✅ | Same (nginx capture overflow, Range abuse, many httpd CVEs) |
| PHP / Java / .NET / Node.js Exploits | ✅ | Same |
| Struts / Spring / Laravel / Rails | ✅ | S2-xxx, Spring4Shell, Rails-family CVE signatures |
| CVE-Based Virtual Patching | ✅ | Core feature: `cve-2010` ... `cve-2026` categories plus the daily `rules_update` (SHA256 verification, atomic swap) |
| Admin / Debug Endpoint Discovery | 🔶 | `admin-interfaces` (LOG) plus CVE-specific debug paths (AEM console, actuator, ...) |

## 10. Reconnaissance

| Attack | Status | Evidence / notes |
| --- | --- | --- |
| Vulnerability Scanner | ✅ | 20+ tools blocked by User-Agent (sqlmap, nikto, nmap, nuclei, Acunetix, ...) |
| Directory / File / Endpoint Enumeration | 🔶 | Scanner UA, `limit`, and rate limits in combination; no behavioral detection of iterative probing |
| Backup File Discovery | ✅ | `sensitive-files.backup-and-dump-files` (`.bak/.old/.sql/.swp`, ...) |
| `.git` / `.env` / Config File Discovery | ✅ | `sensitive-files.credentials-and-config` (hidden behind a 404) |
| phpinfo-style Information Endpoints | ❌ | No rules |
| Swagger/OpenAPI Endpoint Discovery | ❌ | No rules |
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
| Chunked Encoding Abuse | 🔶 | Rejected at the protocol layer (hyper) |
| Multipart Boundary Abuse | 🔶 | 64-part and 1 KiB name limits, malformed bodies inspected raw, part-flood rule |
| JSON/XML Structure Evasion | 🔶 | JSON escapes are decoded; no dedicated structural detection |
| Obfuscated JavaScript / SQL | ✅ | Whitespace- and comment-tolerant regexes |
| WAF Fingerprinting | ❌ | Impossible to hide entirely (the block behavior is itself a signature) |
| Rule Bypass Payloads | ❌ | Cannot be guaranteed; the black-box suite is the ongoing control |

## Core Priority List Summary

| Core item | Status |
| --- | --- |
| SQLi / XSS / Command Injection | ✅ |
| Path Traversal / LFI | ✅ (RFI is ❌) |
| SSRF | 🔶 (metadata and loopback only) |
| XXE / RCE payloads | ✅ |
| Malicious file upload | 🔶 (extension-based) |
| HTTP Protocol Abuse | 🔶 (mostly protocol-layer strictness) |
| Credential Stuffing / Brute Force | 🔶 (per-IP rate limits and bans) |
| Bot | 🔶 (User-Agent signatures only) |
| API Abuse | ❌ to 🔶 (GraphQL, schema, and business logic uncovered) |
| Known CVE Exploits | ✅ (daily virtual patching) |
| HTTP Flood | ✅ |

## Notable Gaps

JWT (including algorithm confusion), GraphQL in general, LDAP/XPath injection,
open redirect, CSS injection, HPP, MIME spoofing, phpinfo/Swagger discovery,
behavioral bot detection, and the business-logic family (IDOR/BOLA, mass
assignment, parameter tampering). CSRF, IDOR, authorization gaps, and session
design cannot be fixed by a WAF at all; Kunato can only assist through custom
response-phase rules. Closing a gap usually means either a YAML rule (most
request-shape gaps) or an engine feature (behavioral and stateful checks).
