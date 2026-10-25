# Manual Lab Shell: A Copy-Paste Walkthrough

This guide starts a small, disposable web-application firewall lab and gives you
a shell inside the "attacker" container. You do not need to write a Compose file
or start containers by hand. Each command has a one-line explanation above it,
and every block is meant to be copied as-is.

## What you are building

```text
your tool container  -- front network -->  Kunato :8080  -- back network -->  fixture
                                                               |
                                                               +-- recording origin
                                                               +-- DVWA + MariaDB
                                                               +-- lab-only CVE-2021-41773 Apache
```

- **Kunato** is the Web Application Firewall under test. It is a reverse proxy:
  it receives HTTP from the tool and forwards it to the fixture.
- **fixture** is an intentionally vulnerable application or a recording server.
  The lab provides three useful fixtures: a recording origin, DVWA, and a
  lab-only Apache 2.4.49 image for CVE-2021-41773.
- **front** is a private Docker network for clients and attack tools. **back**
  is a private network for Kunato's upstream side. Both are `internal`, so the
  tool container cannot reach the internet.
- **tool container** is a throwaway container that contains one selected tool
  and a read-only copy of the lab files under `/lab`.

The command `scripts/security-lab.sh shell` starts the fixtures and Kunato,
opens the tool container, and removes everything when you exit. A new run
directory under `target/security-lab/` keeps the manifest, logs, metrics, and
cleanup record.

### Small glossary

- **WAF**: a firewall that inspects HTTP requests and can block, allow, or log
  them before they reach the application.
- **Reverse proxy**: a server that receives client requests and forwards them to
  an upstream application. Kunato is the reverse proxy in this lab.
- **Fixture**: the deliberately vulnerable application or recording server that
  Kunato protects.
- **DVWA**: Damn Vulnerable Web Application, the SQL-injection fixture.
- **Canary**: a synthetic secret that proves an attack reached the fixture. If
  the canary is returned, the protection failed for that request.
- **Loopback**: the `127.0.0.1` address, which is reachable only from the same
  machine.
- **Internal network**: a Docker network without a route to the internet. The
  lab uses internal networks so attack tools cannot call out.

### Requirements

- A Linux amd64 host with Docker Engine and Docker Compose 2.24.4 or later.
- Python 3.11 or later.
- The repository's Rust toolchain, used by `prepare` to build Kunato.
- A disposable VM for adversarial work. If the host is not disposable, keep all
  exposure on `127.0.0.1` and never publish a fixture.

Run the commands from the repository root. Adjust the `cd` path if your
checkout is elsewhere.

## 0. Prepare once

```sh
# Enter the repository root so the relative lab paths resolve.
cd ~/src/kunato

# Download the pinned images, build the CVE fixture, and build the current Kunato binary.
scripts/security-lab.sh prepare

# Confirm that the prepared images, fixture, and binary match the lock and manifest without downloading.
scripts/security-lab.sh verify
```

`prepare` is the slow step and only needs to be repeated after a Rust source,
image-lock, fixture, or template change. `verify` is a quick offline check.

If `prepare` fails with a Docker buildx error such as
`failed to update builder last activity time: ... read-only file system`, use a
writable Docker config directory for that command only:

```sh
# Create a writable Docker config directory for the build.
mkdir -p /tmp/kunato-docker-config

# Run the preparation with that directory; do not keep DOCKER_CONFIG set for later commands.
DOCKER_CONFIG=/tmp/kunato-docker-config scripts/security-lab.sh prepare
```

## 1. First contact: recording origin and Python

```sh
# Start the recording origin and Kunato, then open a restricted Python shell on the front network.
scripts/security-lab.sh shell --config rules-origin.yaml --tool python
```

The banner tells you what is running:

| Banner line | What it means |
| --- | --- |
| `run:` | The evidence directory for this attempt. |
| `config:` | The Kunato configuration passed to the shell. |
| `protection:` | Whether automatic protection is enabled. Signature-focused configs default to disabled. |
| `network:` | The private Docker network that contains the tool and Kunato. |
| `target:` | The URL to use inside the tool container, normally `http://app.test:8080`. |
| `evidence:` | Where the manual logs, metrics, and attempt record are written. |
| `example:` | A ready-to-run example for the selected tool. |
| `stop:` | How to end the session and trigger cleanup. |

The shell is now inside the tool container. Run these commands:

```sh
# Show the target URL that the lab exported into the shell.
echo "$LAB_TARGET"

# Send one HTTP GET through Kunato to the recording origin and print the status code.
python3 -c "import urllib.request; print('status', urllib.request.urlopen('$LAB_TARGET/health').status)"

# Leave the tool shell; the controller removes the lab containers and networks.
exit
```

Expected output:

```text
http://app.test:8080
status 200
```

`exit` is important: it triggers the automatic `compose down` and writes
`cleanup.json`. If you close the terminal instead, use the cleanup command in
section 7.

## 2. SQL injection: DVWA and sqlmap

```sh
# Start DVWA with MariaDB, start Kunato in front of it, and open a sqlmap tool shell.
scripts/security-lab.sh shell --config rules-dvwa.yaml --tool sqlmap
```

Inside the shell, run this bounded dump:

```sh
# Dump only the lab's synthetic canary table through Kunato with a UNION-only technique.
python3 /sqlmap/sqlmap.py \
  -u "$LAB_TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --batch --level=1 --risk=1 --technique=U \
  --dump -T lab_canary --flush-session --disable-coloring \
  --output-dir=/tmp/sqlmap \
  --user-agent "Mozilla/5.0 KunatoLabClient/1.0"
```

What the flags do:

| Flag | Meaning |
| --- | --- |
| `--batch` | Never ask an interactive question. |
| `--level=1 --risk=1` | Keep the probe count and risk bounded. |
| `--technique=U` | Use UNION-based injection only. |
| `--dump -T lab_canary` | Read the synthetic table seeded by the lab, not a real application table. |
| `--flush-session` | Ignore any cached session from a previous run. |
| `--disable-coloring` | Produce plain text that is easy to read and copy. |
| `--output-dir=/tmp/sqlmap` | Write sqlmap output inside the container's writable temporary area. |
| `--user-agent "Mozilla/5.0 KunatoLabClient/1.0"` | Use the lab's fixed User-Agent so a scanner fingerprint is not the only reason for a block. |

The canary is a random-looking string such as `CANARY-...`. If sqlmap prints
that value, the request reached the database and the WAF missed the attack. If
the dump is blocked, Kunato prevented the protected attempt. The automated
`sqlmap` suite in `lab/README.md` is the authoritative comparison because it
also runs the same dump without Kunato.

For a much faster smoke test, request the database banner instead of a dump:

```sh
# Request the database banner through Kunato with the same bounded sqlmap settings.
python3 /sqlmap/sqlmap.py \
  -u "$LAB_TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --batch --banner --user-agent "Mozilla/5.0 KunatoLabClient/1.0"
```

## 3. CVE-2021-41773: Nuclei

```sh
# Start the lab-only Apache 2.4.49 CVE fixture, start Kunato, and open a Nuclei tool shell.
scripts/security-lab.sh shell --config rules-cve.yaml --tool nuclei
```

The lab exports `LAB_CANARY` for this configuration. Use it directly; there is
no need to copy the random value from the banner.

```sh
# Run the reviewed canary template through Kunato; LAB_CANARY is the per-attempt marker.
nuclei -u "$LAB_TARGET" \
  -t /lab/templates/cve-2021-41773-canary.yaml \
  -var canary="$LAB_CANARY" \
  -var "user_agent=Mozilla/5.0 KunatoLabClient/1.0" \
  -duc -ni -no-color
```

What the flags do:

| Flag | Meaning |
| --- | --- |
| `-u "$LAB_TARGET"` | Send requests to Kunato, not directly to the fixture. |
| `-t ...canary.yaml` | Use the reviewed local template, not a downloaded public template. |
| `-var canary=...` | Tell the template which synthetic file to read. |
| `-var user_agent=...` | Use the lab's fixed User-Agent. |
| `-duc` | Disable update checks because the front network has no internet access. |
| `-ni` | Disable Interactsh callbacks. |
| `-no-color` | Produce plain text. |

A protected run should report no findings. A finding means the traversal reached
the canary file. The automated `nuclei` suite also runs a direct control without
Kunato, which proves that the template can read the canary when the path is not
blocked.

A warning such as `Could not read nuclei-ignore file` is harmless. The scan
still runs; the file is absent because the container's root filesystem is
read-only and `HOME` points at `/tmp`.

## 4. Path discovery: ffuf

```sh
# Start DVWA behind Kunato with the lab's enumeration behavior profile, then open an ffuf tool shell.
scripts/security-lab.sh shell --config rules-ffuf.yaml --tool ffuf
```

```sh
# Probe 29 reviewed paths at a bounded rate and show every response status.
ffuf -u "$LAB_TARGET/FUZZ" \
  -w /lab/plans/ffuf-paths.txt \
  -H "User-Agent: Mozilla/5.0 KunatoLabClient/1.0" \
  -mc all -t 2 -rate 10 -p 0.02 -s
```

What the flags do:

| Flag | Meaning |
| --- | --- |
| `-u "$LAB_TARGET/FUZZ"` | Put each word from the wordlist into the `FUZZ` placeholder. |
| `-w /lab/plans/ffuf-paths.txt` | Use the lab's reviewed 29-path wordlist. |
| `-H "User-Agent: ..."` | Avoid triggering a scanner fingerprint. |
| `-mc all` | Print every response, including 403 and 429. |
| `-t 2` | Use only two concurrent requests. |
| `-rate 10` | Limit the request rate to 10 requests per second. |
| `-p 0.02` | Add a 20 ms delay between requests. |
| `-s` | Suppress the interactive progress display and print only results. |

`rules-ffuf.yaml` enables the enumeration behavior. In a typical run the real
pages return `200`, missing paths return `404`, and after enough distinct
missing paths the protection starts returning `403` or `429`. The exact point
depends on the profile and the fixture.

## 5. Rate limits and bans

### Ban and recovery

```sh
# Start the recording origin with a one-request-per-second ban profile, then open a Python shell.
scripts/security-lab.sh shell --config rules-ban.yaml --tool python
```

```sh
# Send ten requests, hold for three seconds, then probe recovery; the output is JSON.
python3 -B /lab/probe.py ban --requests 10 --hold 3
```

Observed output:

```json
{"id": "ban", "statuses": [429, 429, 429, 429, 429, 429, 429, 429, 429, 429],
 "recovery_status": 200, "held_seconds": 3.0, "banned": true,
 "recovery_error": null, "elapsed_ms": 3015.17}
```

The first requests are rejected with `429`, the source is banned, and the final
recovery probe returns `200` after the ban expires.

### Backpressure

```sh
# Start the origin with a 20-requests-per-second rate guard, then open a Python shell.
scripts/security-lab.sh shell --config rules-backpressure.yaml --tool python
```

```sh
# Send a 100-request burst and print the status mix.
python3 -B /lab/probe.py burst --requests 100
```

Observed result: 20 requests succeeded, 17 were rejected with `503`, and 63 were
rejected with `429`, with zero connection errors. The first burst fills the
per-source budget; the later requests are shed by the rate guard. The JSON
`statuses` array records the exact response for every request.

## 6. Use curl or Burp on the host

Docker does not publish ports from an `internal` network. For host tools, the
lab starts a small loopback-only TCP relay instead.

Terminal 1:

```sh
# Start DVWA behind Kunato, expose it only on 127.0.0.1:8080, and keep running without a tool shell.
scripts/security-lab.sh shell --config rules-dvwa.yaml \
  --publish 127.0.0.1:8080 --no-shell
```

Terminal 2:

```sh
# Request the DVWA SQL-injection page through the loopback relay; Host must match the lab virtual host.
curl -i -H 'Host: app.test' \
  'http://127.0.0.1:8080/vulnerabilities/sqli/?id=1&Submit=Submit' | head
```

For Burp Suite, set the target to `http://127.0.0.1:8080` and add the header
`Host: app.test`. The relay forwards raw TCP, so keep-alive, WebSocket upgrades,
and ordinary HTTP/1.1 requests work.

Use the CVE fixture in the same way:

```sh
# Start the CVE fixture behind Kunato and expose it only on 127.0.0.1:8080.
scripts/security-lab.sh shell --config rules-cve.yaml \
  --publish 127.0.0.1:8080 --no-shell
```

```sh
# Request the fixture root through Kunato.
curl -i -H 'Host: app.test' http://127.0.0.1:8080/
```

If port 8080 is already in use, choose another loopback port and use the same
port in curl or Burp:

```sh
# Start the lab on loopback port 18080 instead of 8080.
scripts/security-lab.sh shell --config rules-dvwa.yaml \
  --publish 127.0.0.1:18080 --no-shell
```

```sh
# Request the fixture through the alternative loopback port.
curl -i -H 'Host: app.test' 'http://127.0.0.1:18080/vulnerabilities/sqli/?id=1&Submit=Submit' | head
```

Stop terminal 1 with Ctrl-C. That removes the relay, containers, and networks.

`--publish` is for plain HTTP configurations. HTTP/2 and HTTP/3 remain covered
by the automated suites.

## 7. Stop and clean up

Preferred: leave the tool shell normally.

```sh
# Exit the tool shell and trigger automatic cleanup.
exit
```

For a `--no-shell` session, press Ctrl-C in the terminal that is running the
lab.

If the terminal was killed or the shell never exited, find the newest lab run
and stop it:

```sh
# Pick the newest run directory; confirm it matches the run: path from the banner.
RUN=$(ls -dt target/security-lab/2*/ | head -1)

# Remove that run's containers, networks, and volumes.
scripts/security-lab.sh down "$RUN"
```

Verify that no lab containers remain:

```sh
# List containers whose names start with kunato-lab-; no output is ideal.
docker ps -a --filter 'name=kunato-lab-' --format '{{.Names}}'
```

Check the cleanup record:

```sh
# Reuse RUN from the block above, or replace it with the run: path from the banner.
cat "$RUN/cleanup.json"
```

All three lists in `cleanup.json` should be empty.

## 8. Options reference

| Option | What it does |
| --- | --- |
| `--config NAME` | Select the Kunato configuration and the matching fixture. |
| `--tool NAME` | Select `python` (default), `sqlmap`, `nuclei`, or `ffuf` for the tool container. |
| `--publish [127.0.0.1:]PORT` | Start a loopback-only relay to Kunato so host tools can reach it. |
| `--no-shell` | Keep the lab running without opening a tool shell; stop it with Ctrl-C. |
| `--protection` | Force automatic protection on. |
| `--no-protection` | Force automatic protection off. |
| `--dvwa-auth` | Enable the seeded DVWA login instead of the default auth-disabled mode. |

With `--dvwa-auth`, the seeded DVWA account is `admin` / `password`.

Supported configurations and their fixtures:

| Configuration | Fixture | Default protection |
| --- | --- | --- |
| `rules-origin.yaml` | Recording origin | Disabled |
| `rules-dvwa.yaml` | DVWA and MariaDB | Disabled |
| `rules-cve.yaml` | Lab-only Apache 2.4.49 | Disabled |
| `rules-ffuf.yaml` | DVWA and MariaDB | Enabled |
| `rules-ban.yaml` | Recording origin | Enabled |
| `rules-backpressure.yaml` | Recording origin | Enabled |
| `rules-availability.yaml` | Recording origin | Enabled |
| `rules-connect.yaml` | Blackhole upstream, no fixture | Disabled |

The shell exports `LAB_TARGET` for every configuration. It exports `LAB_CANARY`
only for `rules-cve.yaml`.

## 9. Troubleshooting

| Symptom | What to do |
| --- | --- |
| `prepare` fails with a buildx activity error under a read-only home directory | Use `DOCKER_CONFIG=/tmp/kunato-docker-config` for `prepare` only, as shown in section 0. |
| `docker compose` says `unknown flag: --project-name` | You still have `DOCKER_CONFIG` set from `prepare`. Unset it, or open a new terminal, and run `shell` normally. |
| `--publish` says the address is already in use | Choose another loopback port, for example `127.0.0.1:18080`. |
| `curl` cannot connect to `127.0.0.1:8080` | Keep terminal 1 running, confirm the banner says `published: http://127.0.0.1:...`, and make sure you did not bind `0.0.0.0`. |
| The fixture returns `404` unexpectedly through `--publish` | Send `Host: app.test`; DVWA and other fixtures can depend on the virtual host. |
| Nuclei warns about `nuclei-ignore` | This is harmless in the read-only container. The scan still runs. |
| `rules-connect.yaml` returns `502` | This is the intended blackhole-upstream case, not a failure. |
| A tool cannot download updates or templates | The front network is `internal`; the lab deliberately has no internet access. Use the pinned local files under `/lab`. |
| The shell or lab appears stuck | Press Ctrl-C and then run the cleanup block in section 7. |

## 10. Evidence and limits

Each run writes:

- `manifest.json` and `input/`: the exact source snapshot and hashes.
- `manual/attempt.json`: the origin nonce used for the health check.
- `manual/health-before.json`: the health response before you started.
- `manual/*.log`: logs from the fixture and Kunato.
- `manual/metrics.json`: Kunato metrics collected at exit.
- `manual/summary.json`: configuration, protection state, tool, and published port.
- `cleanup.json`: proof that containers, networks, and volumes were removed.

Manual mode is for exploration. It does not run a direct control, compare
control and protected evidence, or produce a pass/fail verdict. Promote a
finding to `lab/cases/*.json` or the black-box corpus before treating it as a
regression. The automated server suites in `lab/README.md` provide the
authoritative verdicts.

## 11. Safety rules

- Bind host exposure to `127.0.0.1` only. Never use `0.0.0.0`.
- Never publish DVWA, MariaDB, the CVE fixture, or the recording origin. Only
  Kunato's loopback relay is permitted.
- Do not use host networking for tool containers.
- Treat the `front` network as the untrusted side; do not scan the host, other
  containers, or external networks from it.
- Use a disposable VM for real adversarial work. If the host is shared, keep the
  lab local and stop it when finished.
- The lab is bounded: it does not prove protection for arbitrary applications,
  distributed attacks, or production capacity.

## 12. Quick scenario matrix

| Goal | Command | Then run inside the shell |
| --- | --- | --- |
| Check connectivity | `scripts/security-lab.sh shell --config rules-origin.yaml --tool python` | `python3 -c "import urllib.request; print(urllib.request.urlopen('$LAB_TARGET/health').status)"` |
| SQL injection | `scripts/security-lab.sh shell --config rules-dvwa.yaml --tool sqlmap` | `python3 /sqlmap/sqlmap.py -u "$LAB_TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" --batch --banner --user-agent "Mozilla/5.0 KunatoLabClient/1.0"` |
| CVE-2021-41773 | `scripts/security-lab.sh shell --config rules-cve.yaml --tool nuclei` | The banner's Nuclei command. |
| Path discovery | `scripts/security-lab.sh shell --config rules-ffuf.yaml --tool ffuf` | The banner's ffuf command. |
| Ban and recovery | `scripts/security-lab.sh shell --config rules-ban.yaml --tool python` | `python3 -B /lab/probe.py ban --requests 10 --hold 3` |
| Rate-guard burst | `scripts/security-lab.sh shell --config rules-backpressure.yaml --tool python` | `python3 -B /lab/probe.py burst --requests 100` |
| Host curl or Burp | `scripts/security-lab.sh shell --config rules-dvwa.yaml --publish 127.0.0.1:8080 --no-shell` | Use curl or Burp in a second terminal. |

For the automated, deterministic agentic chain that covers SQL injection, command
injection, PHP upload, and CVE traversal, run
`scripts/security-lab.sh run --sandbox-suite agentic`; see [README.md](README.md)
for the suite description.
