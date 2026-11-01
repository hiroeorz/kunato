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
| CVE-2026-116011 | Crow | Bound JSON nesting depth in inspected request bodies | Deeply nested JSON below the body-size limit exhausts the worker stack; the rule schema has no depth target and the engine has no generic JSON depth cap (only GraphQL and form nesting limits) | 2026-11-02 | open |
| CVE-2026-119762 | Axigen Mail Server | Bound XML/SOAP nesting depth (verify) | The coverage note says body and form limits stop it, but form limits apply to multipart and URL-encoded bodies; XML nesting is not depth-checked | 2026-11-02 | verify |
