---
name: kunato-ruby-coverage
description: Use when hardening Kunato against Ruby, Ruby on Rails, and the Rack/Puma/gem ecosystem: researching rubygems advisories and Rails default-configuration exposure, appending attack requests to blackbox/requests/blocked.txt, adding near-miss benign guards to blackbox/requests/allowed.txt, running the black-box test, implementing rules and engine changes until block misses and false blocks are zero, and recording the Rails coverage in TODO.md. Triggers - Ruby, Rails, Ruby on Rails, rubygems, Rack, Puma, Devise, Rails CVE, Active Storage, Marshal, !ruby YAML, master.key, sidekiq, Rails default config, blocked.txt, allowed.txt, TODO.md.
---

# Kunato Ruby and Rails coverage workflow

Extend the [kunato-cve-coverage](../kunato-cve-coverage/SKILL.md) loop to the Ruby
and Rails surface: gem advisories, framework default exposure, Ruby-internal
serialization formats, and the parser quirks of the Rack stack. Run the
kunato-cve-coverage steps as written — request-list syntax, match semantics, the
black-box scripts, the counters, the TODO.md recording, and the final checks are
identical — and only replace the enumeration and design steps with the
Ruby-specific guidance below.

## Step 1: Enumerate Ruby and Rails attack patterns

Sources, in preference order:

- The RubySec `ruby-advisory-db` and the GitHub Advisory database with the
  `rubygems` ecosystem, then the Rails security announcement forum and the
  Rack, Puma, and Devise release notes.
- Apply the repository policy: CVSS base score 7.0 or higher and reproducible
  with an HTTP request. Rails component advisories often score below 7.0 (XSS,
  ReDoS); skip them for bundled signatures and leave a left-out comment when
  they are notable.

Cover both halves of the surface:

- **Vulnerabilities**: advisories for `rails`, `actionpack`, `activerecord`,
  `activesupport`, `actionview`, `actionmailer`, `activestorage`, `actiontext`,
  `rack`, `puma`, `devise`, and any gem the deployment uses. Extract the request
  shape from the advisory, not from exploit headlines; when a writeup publishes
  a raw PoC, translate it into the request-list syntax.
- **Default and development exposure**: endpoints, dashboards, and files that
  ship enabled or reachable and must be closed in production. Use the catalog
  below; add one section per family with a compact banner.

Request-shape notes specific to this stack:

- Multipart bodies need real CR/LF: keep them in
  `blackbox/requests/payloads/` and reference them with `body_file=`.
- Chunked uploads use `chunked=1`; HTTP/2 framing probes use `proto=h2c`.
- Marshal payloads appear base64-encoded (`BAh7...`), percent-encoded
  (`%04%08`), or in cookies; put them in the presentation the vulnerability
  uses (session cookie, query parameter, form field).
- Validate the list parses with the same command as kunato-cve-coverage step 1.

## Step 2: Add near-miss benign guards

Every Ruby/Rails rule family has a legitimate twin that must keep passing:

- Active Storage signed URLs: JSON-then-base64 wrappers that never contain the
  literal Marshal prefix; functional blob/redirect/representation paths.
- Functional framework routes: `/rails/active_storage/*`,
  `/rails/action_mailbox/*` (mail-provider ingress), and `/cable`.
- Dashboards: `/sidekiq`, `/pghero`, `/flipper`, `/blazer`, `/delayed_job`,
  and `/good_job` are legitimately deployed behind application auth.
- YAML anchors and aliases (`&anchor` / `*alias`) without `!ruby` tags.
- Rails-style base64 cursors and tokens that are not Marshal dumps.
- `redirect_uri` and payment `return_url` values, which the open-redirect rule
  intentionally ignores.

## Step 3: Run the black-box test

Same script and counters as kunato-cve-coverage step 3. Do not proceed until the
run reports zero block misses and zero false blocks.

## Step 4: Implement the defenses

Rule design guidance for this surface:

- Marshal signatures match the base64 form (`BAh7`, the base64 of the
  `\x04\x08` Marshal header) and the encoded raw form (`%04%08`). Never match
  raw `\x04\x08` in bodies: those two control bytes occur naturally in binary
  uploads.
- YAML signatures anchor on `!ruby/` tags, never on anchors or aliases.
- Development-only routes belong in `rails-debug-endpoints` (BLOCK);
  dashboards belong in `admin-interfaces` (LOG) until the operator allowlists
  admin addresses.
- Secret and configuration files extend `sensitive-files` and answer 404.
- Engine behavior that must not regress:
  - Multipart inspection flattens every declared boundary (up to
    `MAX_MULTIPART_BOUNDARIES` in `src/decoding.rs`); more candidates fall back
    to the raw percent passes. Rack parses the last boundary, so dropping the
    union would reopen the CVE-2026-26961 bypass class.
  - Signed IDs and `ActiveSupport::MessageVerifier` payloads are tamper-evident;
    do not attempt static signatures for them.
- Regenerate `dist/rules.yaml` after rule changes and return to step 3.

## Step 5: Record the coverage in TODO.md

Update the "Rails / Laravel" row and the "Ruby on Rails coverage" table under
CMS and Framework Attacks, plus the Multipart Boundary Abuse and Unsafe
Deserialization rows when they move. Keep statuses honest: generic shape rules
and dev-only route blocks are Covered, dashboard LOGging and wire-method or
host-policy limitations are Partial, and patch-side-only issues are Gap with a
"patch-side" note. Refresh the snapshot date and rule count.

## Step 6: Finish

Run the repository checks from AGENTS.md (and the `blackbox/` variants when that
crate changed), then report per kunato-cve-coverage step 6. Do not commit unless
the user asks.

## Ruby/Rails surface catalog

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

Ruby serialization shapes:

- Marshal: base64 `BAh7`, encoded raw `%04%08`, in cookies, query, or params
- YAML: `!ruby/object:`, `!ruby/hash:`, `!ruby/struct:`, `!ruby/module`,
  `!ruby/sym`

Parser and routing quirks:

- Multipart boundary differentials (CVE-2026-26961 class): every declared
  boundary is one parser's interpretation
- Chunked multipart without Content-Length (CVE-2026-34829) and escape-heavy
  part headers (CVE-2026-34827)
- `_method` / `X-HTTP-Method-Override`: Rack accepts standard methods only;
  method rules see the wire method
- Host, `X-Forwarded-Host`, and `Forwarded` spoofing: a host allowlist policy
  does not exist yet

Not fixable by the WAF (patch- or application-side):

- Active Storage libvips variant operations (CVE-2026-66066), Rack::Static
  prefix exposure (CVE-2026-34785)
- CSRF, strong parameters and mass assignment, authorization, signed-ID
  forgery, `secret_key_base` exposure

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
