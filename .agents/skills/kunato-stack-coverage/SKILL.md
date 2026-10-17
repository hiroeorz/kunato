---
name: kunato-stack-coverage
description: Use when hardening Kunato against a web stack's ecosystem - Ruby on Rails, Django/Python, Next.js, and Node.js/npm: researching gem/PyPI/npm advisories and framework default-configuration exposure, appending attack requests to blackbox/requests/blocked.txt, adding near-miss benign guards to blackbox/requests/allowed.txt, running the black-box test, implementing rules and engine changes until block misses and false blocks are zero, and recording the stack coverage in TODO.md. Triggers - Ruby, Rails, Ruby on Rails, rubygems, Rack, Puma, Devise, Rails CVE, Active Storage, Marshal, !ruby YAML, master.key, sidekiq, Django, Python, PyPI, pickle, !!python, DEBUG page, Next.js, Node.js, npm, prototype pollution, __nextjs, webpack-hmr, blocked.txt, allowed.txt, TODO.md.
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
  and `npm` (Node.js security releases) via the GitHub Advisory Database and
  OSV.dev.
- Framework announcements and release notes: Rails, Rack/Puma/Devise, Django,
  Next.js.
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

Never add real attacks to `allowed.txt`, and do not remove existing guards.

## Step 3: Run the black-box test

Same script and counters as kunato-cve-coverage step 3. Do not proceed until the
run reports zero block misses and zero false blocks.

## Step 4: Implement the defenses

Design guidance:

- Per-stack categories (keep new paths in the right one):
  - `rails-debug-endpoints`, `django-debug-endpoints`, `nextjs-dev-endpoints`
    (BLOCK, development-only routes)
  - `ruby-deserialization`, `python-deserialization` (BLOCK, serialization
    shapes)
  - `prototype-pollution` (BLOCK, `__proto__` and constructor-prototype paths)
  - `sensitive-files` (404: `master.key`, `settings.py`, logs, storage)
  - `admin-interfaces` (LOG: Rails and other dashboards)
- Marshal signatures match base64 (`BAh7`) and encoded raw (`%04%08`); pickle
  signatures match base64 (`gAJ`/`gAS`/`gAR`) and encoded raw (`%80%0[24]`).
  Never match raw `\x04\x08` or `\x80` bytes in bodies: those bytes occur
  naturally in binary uploads.
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

## Node.js and npm catalog

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
