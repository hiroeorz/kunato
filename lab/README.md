# Local security lab

This is the first implementation of the [adversarial testing design](../docs/security-testing.md):
an isolated recording origin, direct receipt controls, Kunato request-rejection
regressions, and a curated goTestWAF campaign. It measures signature behavior;
the origin is not a vulnerable application and cannot prove exploit prevention.
Nuclei/CVE fixtures, DVWA/sqlmap, authenticated ZAP workflows, and load/protocol
campaigns remain subsequent milestones.

## Run locally

Requirements: a Linux amd64 host, Docker Engine with Compose 2.24.4 or later,
Python 3.11 or later, and the repository's Rust toolchain. Use a disposable VM
for adversarial work. The initial Compose environment has no published ports,
host networking, privileged containers, or Docker-socket mounts. Internal Docker
networks do not by themselves establish isolation from every host service.

```sh
# Preparation may download the locked images and build the current Rust source.
scripts/security-lab.sh prepare

# Verify cached images, binary, and source hashes without downloading anything.
scripts/security-lab.sh verify

# Direct controls, followed by WAF inspection of attacks and benign guards.
scripts/security-lab.sh run

# Run the receipt regressions and the real goTestWAF binary.
scripts/security-lab.sh run --campaign gotestwaf
```

Execution always uses local image IDs with `pull_policy: never`; it does not install
or update scanners, rules, or templates. `prepare` must be repeated after a Rust
source or image-lock change. Rules and lab cases are copied from the current
worktree into an immutable input snapshot at the beginning of each run.

Each run prints its directory under `target/security-lab/`. It retains:

- `manifest.json`: commit, source/binary hashes, image digests, and input hashes;
- `input/`: exact rules, case definitions, scanner plans, code, and binary;
- `control/` and `replay/`: fresh attempt IDs, health probes, client exchanges,
  origin events, Kunato JSON logs, and metrics;
- `gotestwaf-control/` and `gotestwaf/`: direct/protected tool reports and origin
  observations when the scanner is selected;
- `report.json` and `report.md`: case verdicts, counts, and diagnostics.
- `commands.jsonl` and `cleanup.json`: executed commands and verification that
  the run's containers, networks, and named volumes have been removed.

```sh
scripts/security-lab.sh report target/security-lab/<run-id>
scripts/security-lab.sh down target/security-lab/<run-id>
```

Reports exit with failure when a required control or observation is missing,
a tool fails, an attack reaches the origin, a legitimate exchange changes, or
the campaign is inconclusive. Containers and project networks are removed after
the run, including on ordinary failure. `down` cleans only the identified lab
project if a controller was forcibly interrupted; evidence is retained.

## Evidence and case changes

`cases/smoke.json` pairs SQLi, XSS, and traversal probes with benign counterparts
and includes legitimate 302/401/404 responses. These are general attack-class
probes, not CVE coverage claims. Every case executes with an ordinary fixed
User-Agent. The lab removes the whole private-source `trusted-sources` category
and disables automatic protection. YAML rule-level throttles remain present;
the short smoke sequence does not target those throttled routes.

Direct controls must prove the exact method, target, body hash, origin nonce,
and expected status. The protected attempt runs against newly created services.
A block passes only with an expected 403, a matching non-rate-limited Kunato rule
event, no origin receipt, and successful surrounding normal probes. A 403 from
the origin is a gap. A reset or timeout is inconclusive.

The controller derives a one-payload/one-encoder/one-placement goTestWAF plan
from the same smoke inputs. Query and body placement are preserved; the recording
path is namespaced for correlation. goTestWAF escapes RawRequest query values,
so preencoded values are decoded before generating its plan. Direct controls
verify decoded query parameters, method, and body hash to catch accidental
double encoding or other request transformations. Direct scanner controls must
receive every planned case with the ordinary User-Agent before protected results
are evaluated.
Original JSON scanner output is retained beside the independent origin verdicts.
This small stable plan is a regression gate, not the full upstream goTestWAF
catalog or an estimate of overall WAF efficacy.

For a new discovery, preserve the original tool request, minimize it, add an
attack and nearby benign guard, reproduce the failure, fix the appropriate rule
or engine mechanism, and re-run both the regression and original campaign.
Use the CVE skill and update the coverage documents when evidence changes.
This lab never edits rules, commits fixes, or publishes managed rule updates.

Validate collector and verdict failures locally:

```sh
python3 -m unittest discover -s lab/tests -v
```

The separate security-lab workflow runs these checks and the isolated smoke
campaign for relevant pull requests and supports manual execution. The daily
CVE publishing workflow is unchanged.
