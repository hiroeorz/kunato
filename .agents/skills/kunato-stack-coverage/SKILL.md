---
name: kunato-stack-coverage
description: Use when hardening Kunato against a web stack's ecosystem - Ruby on Rails, Django/Python, Next.js, Node.js/npm, PHP/Laravel, Java/Spring, frontend dev servers, and AI/notebook services: researching package and framework advisories and default-configuration exposure, appending attack requests to blackbox/requests/blocked.txt, adding near-miss benign guards to blackbox/requests/allowed.txt, running the black-box test, implementing rules and engine changes until block misses and false blocks are zero, and recording the stack coverage in TODO.md. Triggers - Ruby, Rails, rubygems, Rack, Puma, Devise, Marshal, !ruby YAML, master.key, sidekiq, Django, Python, PyPI, pickle, !!python, DEBUG page, Next.js, Node.js, npm, prototype pollution, __nextjs, webpack-hmr, PHP, Composer, Laravel, Telescope, debugbar, Horizon, Java, Spring, Actuator, heapdump, Jolokia, Maven, rO0AB, Vite, Nuxt, SvelteKit, @vite, @fs, Ollama, Jupyter, Gradio, Flowise, vLLM, blocked.txt, allowed.txt, TODO.md.
---

# Kunato stack coverage workflow

Extend the [kunato-cve-coverage](../kunato-cve-coverage/SKILL.md) loop to the
platform-specific surface: package-ecosystem advisories, framework default and
development exposure, language-internal serialization formats, and the protocol
or parser quirks of each runtime. Run the kunato-cve-coverage steps as written —
request-list syntax, match semantics, the black-box scripts, the counters, the
TODO.md recording, and the final checks are identical — and only replace the
enumeration and design steps with the per-stack guidance below.

## Step 1: Enumerate attack patterns

Sources, in preference order:

- Package advisories in machine-readable form first: `rubygems`
  (ruby-advisory-db), `pip` (Django security announcements, Python advisories),
  `npm` (Node.js security releases), `composer` (Packagist, FriendsOfPHP), and
  `maven` (Spring Security advisories) via the GitHub Advisory Database and
  OSV.dev.
- Framework announcements and release notes: Rails, Rack/Puma/Devise, Django,
  Next.js, Laravel, Spring, Vite/Nuxt, and the AI services in use (Gradio,
  Open WebUI, Flowise, vLLM).
- Apply the repository policy: CVSS base score 7.0 or higher and reproducible
  with an HTTP request. Framework advisories often score below 7.0 (XSS, ReDoS);
  skip them for bundled signatures and leave a left-out comment when notable.

Cover both halves of each surface:

- **Vulnerabilities**: advisories for the frameworks and gems/packages the
  deployment uses. Extract the request shape from the advisory, not from exploit
  headlines; translate published PoCs into the request-list syntax.
- **Default and development exposure**: endpoints, dashboards, and files that
  ship enabled or reachable and must be closed in production. Use the catalogs
  below.

Request-shape notes:

- Multipart bodies need real CR/LF: keep them in
  `blackbox/requests/payloads/` and reference them with `body_file=`.
- Chunked uploads use `chunked=1`; HTTP/2 framing probes use `proto=h2c`.
- Serialization payloads appear in the presentation the vulnerability uses:
  Marshal base64 (`BAh7`) in cookies, pickle base64 (`gAJ`/`gAS`) in session
  cookies, percent-encoded raw bytes, or YAML tags in bodies.
- Validate the list parses with the same command as kunato-cve-coverage step 1.

## Step 2: Add near-miss benign guards

Each stack has legitimate traffic that merely resembles the payloads:

- Rails: Active Storage signed URLs, functional `/rails/active_storage/*` and
  `/rails/action_mailbox/*` routes, ops dashboards behind application auth,
  YAML anchors/aliases without `!ruby` tags, `redirect_uri` values.
- Django/Python: `/admin/` and `/static/admin/*`, `!!str`/`!!int` YAML tags,
  base64 cursors that are not pickles, benign `settings` API paths.
- Next.js: `/_next/static/*`, `/_next/data/*`, `/_next/image`, ordinary
  application routes.
- Node.js: `Object.prototype.hasOwnProperty` in code snippets, ordinary
  `constructor` query values.
- PHP/Laravel: `/horizon` behind application auth, benign `O:2` text that is
  not a serialized object, `composer`-named API paths.
- Java: `/actuator/health` and `/actuator/info` monitoring probes.
- Frontend: `/_nuxt/*` production assets and `@user` profile routes.
- AI services: Ollama read endpoints (`/api/tags`, `/api/status`) and
  generation calls (`/api/generate`).

Never add real attacks to `allowed.txt`, and do not remove existing guards.

## Step 3: Run the black-box test

Same script and counters as kunato-cve-coverage step 3. Do not proceed until the
run reports zero block misses and zero false blocks.

## Step 4: Implement the defenses

Design guidance:

- Per-stack categories (keep new paths in the right one):
  - `rails-debug-endpoints`, `django-debug-endpoints`, `nextjs-dev-endpoints`,
    `laravel-debug-endpoints`, `vite-dev-endpoints` (BLOCK, development-only
    routes)
  - `spring-actuator` (BLOCK, secret- and state-dumping Actuator endpoints)
  - `ai-service-management` (BLOCK, Ollama model management and Jupyter
    kernels/terminals)
  - `ruby-deserialization`, `python-deserialization`, `php-deserialization`,
    `java-deserialization` (BLOCK, serialization shapes)
  - `prototype-pollution` (BLOCK, `__proto__` and constructor-prototype paths)
  - `sensitive-files` (404: `master.key`, `settings.py`, `composer.json`, logs,
    storage)
  - `admin-interfaces` (LOG: Rails, Laravel Horizon, and other dashboards)
- Marshal signatures match base64 (`BAh7`) and encoded raw (`%04%08`); pickle
  signatures match base64 (`gAJ`/`gAS`/`gAR`) and encoded raw (`%80%0[24]`);
  Java streams match `rO0AB` and `%AC%ED%00%05`; PHP objects match `O:`/`C:`
  quoted values. Never match raw `\x04\x08`, `\x80`, or `\xac\xed` bytes in
  bodies: those bytes occur naturally in binary uploads.
- YAML signatures anchor on `!ruby/` or `!!python/` tags, never on anchors.
- Response-phase rules (for example the Django DEBUG page) have no request-line
  tests; say so when recording coverage.
- Engine behavior that must not regress:
  - Multipart inspection flattens every declared boundary (up to
    `MAX_MULTIPART_BOUNDARIES` in `src/decoding.rs`); more candidates fall back
    to the raw percent passes.
  - Signed IDs, Django signed cookies, and `MessageVerifier` payloads are
    tamper-evident; do not attempt static signatures for them.
- Regenerate `dist/rules.yaml` after rule changes and return to step 3.

## Step 5: Record the coverage in TODO.md

Update the row for the stack in CMS and Framework Attacks and the matching
coverage table ("Ruby on Rails coverage", "Django, Next.js, and Node.js
coverage"), plus the deserialization and multipart rows when they move. Keep
statuses honest: generic shape rules and dev-only route blocks are Covered,
dashboard LOGging, preview-mode ambiguity, and password/URL policy limitations
are Partial, and patch-side-only or protocol-level issues are Gap with a note.
Refresh the snapshot date and rule count.

## Step 6: Finish

Run the repository checks from AGENTS.md (and the `blackbox/` variants when that
crate changed), then report per kunato-cve-coverage step 6. Do not commit unless
the user asks.

## Ruby and Rails catalog

Development-only endpoints (BLOCK; never valid in production):

- `/rails/info/routes`, `/rails/info/properties`
- `/rails/mailers[/...]`, `/rails/conductor/action_mailbox/...`
- `/letter_opener[/...]`, web-console and better_errors cues

Ops dashboards (LOG by default, BLOCK after allowlisting):

- `/sidekiq`, `/pghero`, `/flipper`, `/blazer`, `/delayed_job`, `/good_job`
- Mission Control mounts at `/jobs` by default, which is usually
  indistinguishable from an application path; only cover it when the deployment
  mounts it elsewhere.

Secrets, configuration, logs, storage (404):

- `/config/master.key`, `/config/credentials/*.key`, `/config/credentials.yml.enc`
- `/config/database.yml`, `/config/storage.yml`, `/config/secrets.yml`
- `/log/*.log`, `/storage/**` (the Active Storage DiskService root)

Serialization shapes:

- Marshal base64 `BAh7`, encoded raw `%04%08`, in cookies, query, or params
- YAML `!ruby/object:`, `!ruby/hash:`, `!ruby/struct:`, `!ruby/module`,
  `!ruby/sym`

## Django and Python catalog

Development exposure (BLOCK or 404):

- `/__debug__/` and `/__debug__/render_panel/` (django-debug-toolbar)
- `settings.py` and `local_settings.py` probes (SECRET_KEY discovery)
- The technical 404/500 page while `DEBUG = True` (response phase)

Serialization shapes:

- Pickle base64 `gAJ`/`gAS`/`gAR`, encoded raw `%80%0[24]`
- YAML `!!python/object`, `!!python/object/apply`, `!!python/name`,
  `!!python/module`

Application-side classes: GeoDjango raster operations, cache-middleware
disclosure, validator ReDoS, and serializer salt/namespace issues have no
stable request shapes; record them as left-out comments.

## Next.js catalog

Development-only endpoints (BLOCK):

- `/__nextjs_original-stack-frame`, `/__nextjs_launch-editor`, other `/__nextjs*`
- `/_next/webpack-hmr` (hot module replacement)

Bundled CVE shapes: middleware subrequest bypass (CVE-2025-29927), image
optimizer SSRF (CVE-2024-34351), RSC route variants and deserialization, and
route-match cache poisoning. Preview/draft mode (`__prerender_bypass`,
`__next_preview_data`) is indistinguishable from legitimate preview traffic.

## PHP and Laravel catalog

Development and ops exposure:

- `/telescope[/...]` and `/_debugbar[/...]` (BLOCK, debug dashboards)
- `/horizon` (LOG through `admin-interfaces`, BLOCK after allowlisting)
- `composer.json` and `composer.lock` (404), plus `.env` (generic)

Serialization shapes:

- Serialized objects `O:<len>:"Class"...` and custom `C:<len>:"..."` values in
  cookies, query, or body

Application-side classes: Laravel/Symfony CVEs are bundled only with stable
request shapes (for example the Ignition endpoint); WordPress plugin CVEs stay
out of scope unless the plugin is actually deployed.

## Java and Spring catalog

Exposure (BLOCK; `health` and `info` stay open):

- `/actuator/env`, `/actuator/heapdump`, `/actuator/threaddump`,
  `/actuator/mappings`, `/actuator/beans`, `/actuator/configprops`,
  `/actuator/jolokia[/...]`, `/actuator/loggers`, `/actuator/httptrace`,
  `/actuator/shutdown`, `/actuator/sessions`, and the other dumping endpoints

Serialization shapes:

- Base64 `rO0AB` (the `\xac\xed\x00\x05` stream header) and the encoded raw
  `%AC%ED%00%05` in cookies, query, or body

## Frontend dev-server catalog

Development-only endpoints (BLOCK):

- `/@fs/...` (Vite arbitrary file read), `/@vite/*`, `/@id/*`, `/__vite_ping`
- `/__nuxt_devtools__/*`

Production assets (`/_nuxt/*`, hashed bundles) and `@user` profile paths must
stay allowed.

## AI and notebook service catalog

Management endpoints (BLOCK; deployments that drive them through Kunato need an
override):

- Ollama: `/api/pull`, `/api/push`, `/api/create`, `/api/delete`, `/api/copy`
- Jupyter: `/api/kernels[/...]`, `/api/terminals[/...]`

Read and generation endpoints (`/api/tags`, `/api/generate`, `/api/status`)
stay open. Gradio, Open WebUI, Flowise, and vLLM advisories (FileExplorer
traversal, `proxy_url` SSRF, sandbox escapes, OAuth token leaks) have no stable
request signatures; rely on the generic pickle/traversal/SSRF classes and the
left-out comments.

## Key files

- Prototype pollution: `__proto__`, `constructor[prototype]`,
  `constructor.prototype` in query, body, and cookies
- Template engines (EJS `<%=`, Pug `#{}`, Handlebars `{{ }}`) are covered by
  the generic `ssti` category
- npm package CVEs: bundle only with a stable request shape; keep the rest on
  the daily watch
- Runtime classes (llhttp smuggling, permission model) are protocol and engine
  scope, not URL signatures

## Key files

- `rules.example.yaml`, `dist/rules.yaml` (`scripts/update-dist-rules.sh`),
  `TODO.md`
- `blackbox/requests/blocked.txt`, `allowed.txt`, `payloads/`
- `src/decoding.rs` (body decoding and multipart flattening),
  `src/rules/matcher.rs` (match semantics)
- `tests/proxy.rs` (integration coverage for engine changes)

## Scripts

- The test cycle and log analysis scripts live in the companion skill:
  `.agents/skills/kunato-cve-coverage/scripts/run_coverage_test.sh` and
  `analyze_blackbox.py`.
