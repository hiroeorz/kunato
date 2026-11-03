# Engine gaps

Vulnerabilities the daily CVE intake could not cover with a rule because the
change belongs in the engine rather than in the rule set. The daily agent
appends a row here instead of publishing a rule the newest release cannot
parse: one unknown construct makes every install reject the whole candidate
set, so the rule has to wait for a release.

A row is a request for a source change, not for a rule. Resolve it by
implementing the capability and cutting a release, then delete the row: git
history keeps the record and this file stays short. The coverage row still
tracks the rule, which can follow in a later daily update.

Status values: `open` (not addressed) and `verify` (the existing mitigation or
the need for a source change is unconfirmed). Delete a row once its release
ships, or once a `verify` confirms the existing mitigation; git history keeps
the record. Do not keep `fixed` rows. Keep each row on one line; a `|` inside
a cell breaks the table.

| CVE | Product | Engine change | Why a rule cannot cover it | Reported | Status |
| --- | --- | --- | --- | --- | --- |

No open engine gaps as of 2026-11-03: generic JSON/XML nesting depth and the
GraphQL batch/depth differentials are handled by the request-body checks added
in this release.
