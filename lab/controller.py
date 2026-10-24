"""Prepare frozen inputs and run isolated, observable local WAF suites."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from evidence import (USER_AGENT, judge_availability, judge_crs, judge_ffuf,
                      judge_ffuf_behavior, judge_gotestwaf, judge_mutations, judge_load,
                      judge_nuclei, judge_protocol, judge_replay, judge_slow,
                      judge_sqlmap, judge_zap, judge_zap_workflow, origin_response,
                      read_jsonl, summarize, validate_cases, validate_ffuf_cases,
                      validate_mutations, validate_protocol, verify_origin)

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
WORK = ROOT / "target/security-lab"
PREPARED = WORK / "prepared"
COMMAND_JOURNAL = None

FFUF_PROTECTION = """protection:
  enabled: true
  max_connections_per_ip: 32
  max_connections: 1024
  requests_per_second: 20
  burst: 60
  global_requests_per_second: 2000
  max_tracked_ips: 100000
  aggregate_ipv6_prefix: 64
  ban:
    violations: 5
    window: 10s
    duration: 60s
    max_duration: 1h
  behavior:
    enabled: true
    window: 60s
    min_requests: 10
    enumeration:
      enabled: true
      action: BLOCK
      not_found_ratio: 0.5
      distinct_paths: 8
    auth:
      enabled: false
    global_auth:
      enabled: false
"""

AVAILABILITY_TIMEOUTS = """timeouts:
  header_read: 5s
  body_read: 2s
  upstream_connect: 1s
  upstream_response: 1s
  shutdown_grace: 10s
  connection_idle: 60s
"""

AVAILABILITY_PROTECTION = """protection:
  enabled: true
  max_connections_per_ip: 8
  max_connections: 64
  requests_per_second: 1000
  burst: 1000
  global_requests_per_second: 10000
  max_tracked_ips: 100
  aggregate_ipv6_prefix: 64
  ban:
    violations: 1000
    window: 60s
    duration: 1s
    max_duration: 1s
  behavior:
    enabled: false
"""


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def tree_hash(directory):
    digest = hashlib.sha256()
    for path in sorted(path for path in directory.rglob("*") if path.is_file()):
        digest.update(str(path.relative_to(directory)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def source_hash():
    digest = hashlib.sha256()
    for path in sorted([ROOT / "Cargo.toml", ROOT / "Cargo.lock", *ROOT.glob("src/**/*.rs")]):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "kunato-lab/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with destination.open("wb") as sink:
            shutil.copyfileobj(response, sink)


def command(args, *, env=None, timeout=60, check=True, log=None, quiet=False):
    if not quiet:
        print("+ " + " ".join(str(arg) for arg in args), flush=True)
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False)
    if COMMAND_JOURNAL and not quiet:
        with COMMAND_JOURNAL.open("a") as journal:
            journal.write(json.dumps({"argv": [str(arg) for arg in args], "exit_code": result.returncode}) + "\n")
    if log:
        log.write_text(result.stdout)
        log.with_suffix(log.suffix + ".stderr").write_text(result.stderr)
    if check and result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}: {args}\n{result.stderr[-4000:]}\n{result.stdout[-2000:]}")
    return result


def prepare():
    lock = json.loads((LAB / "artifacts.lock.json").read_text())
    if lock["schema_version"] != 1 or any(not re.search(r"@sha256:[a-f0-9]{64}$", image)
                                          for image in lock["images"].values()):
        raise ValueError("Image lock must use schema 1 and immutable image digests")
    fixture = lock["fixtures"]["httpd_cve_2021_41773"]
    fixture_dir = ROOT / fixture["build_context"]
    if tree_hash(fixture_dir) != fixture["source_sha256"]:
        raise ValueError("CVE fixture sources changed; update artifacts.lock.json")
    if sha256(ROOT / fixture["template"]) != fixture["template_sha256"]:
        raise ValueError("Nuclei template changed; update artifacts.lock.json")
    PREPARED.mkdir(parents=True, exist_ok=True)
    command(["docker", "version", "--format", "{{.Server.Version}}"])
    images = {}
    for name, reference in lock["images"].items():
        inspected = command(["docker", "image", "inspect", reference], check=False)
        if inspected.returncode:
            command(["docker", "pull", "--platform", lock["platform"], reference], timeout=900)
            inspected = command(["docker", "image", "inspect", reference])
        image = json.loads(inspected.stdout)[0]
        if image["Architecture"] != lock["platform"].split("/")[1]:
            raise ValueError("Prepared image does not match the selected platform")
        images[name] = {"reference": reference, "id": image["Id"],
                        "digests": image.get("RepoDigests", []), "architecture": image["Architecture"]}
    tools = {}
    for name, tool in lock.get("tools", {}).items():
        binary = PREPARED / name
        if not binary.exists() or sha256(binary) != tool["binary_sha256"]:
            archive = WORK / f"{name}-{tool['sha256'][:16]}.tar.gz"
            if not archive.exists() or sha256(archive) != tool["sha256"]:
                download(tool["url"], archive)
            if sha256(archive) != tool["sha256"]:
                raise ValueError(f"Downloaded {name} archive does not match the lock")
            with tarfile.open(archive, "r:gz") as bundle:
                member = bundle.getmember(name)
                if not member.isfile():
                    raise ValueError(f"{name} archive does not contain a regular file")
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError(f"Cannot read {name} from its archive")
                binary.write_bytes(source.read())
            binary.chmod(0o755)
        if sha256(binary) != tool["binary_sha256"]:
            raise ValueError(f"Prepared {name} binary does not match the lock")
        tools[name] = {"version": tool["version"], "url": tool["url"],
                       "sha256": tool["sha256"], "binary_sha256": tool["binary_sha256"]}
    command(["docker", "build", "--platform", lock["platform"], "--network", "none",
             "--build-arg", f"BASE={lock['images'][fixture['base_image']]}",
             "--tag", fixture["image_tag"], str(fixture_dir)], timeout=600)
    built = json.loads(command(["docker", "image", "inspect", fixture["image_tag"]]).stdout)[0]
    if tree_hash(fixture_dir) != fixture["source_sha256"]:
        raise ValueError("CVE fixture sources changed during the build; repeat prepare")
    fixtures = {"httpd_cve_2021_41773": {
        "reference": fixture["image_tag"], "id": built["Id"],
        "source_sha256": fixture["source_sha256"],
        "template_sha256": fixture["template_sha256"],
        "base_reference": lock["images"][fixture["base_image"]],
    }}
    source_before = source_hash()
    command(["cargo", "build", "--release", "--locked"], timeout=900)
    if source_hash() != source_before:
        raise ValueError("Rust sources changed during the build; repeat prepare")
    shutil.copy2(ROOT / "target/release/kunato", PREPARED / "kunato")
    manifest = {"schema_version": 1, "platform": lock["platform"], "images": images,
                "fixtures": fixtures, "tools": tools, "tool_versions": lock["tool_versions"],
                "binary_sha256": sha256(PREPARED / "kunato"), "source_sha256": source_hash(),
                "lock_sha256": sha256(LAB / "artifacts.lock.json")}
    write_json(PREPARED / "manifest.json", manifest)
    print(f"Prepared inputs: {PREPARED}")


def prepared_inputs():
    manifest = json.loads((PREPARED / "manifest.json").read_text())
    lock = json.loads((LAB / "artifacts.lock.json").read_text())
    if manifest["lock_sha256"] != sha256(LAB / "artifacts.lock.json"):
        raise ValueError("Image lock changed; run prepare")
    if manifest["source_sha256"] != source_hash() or manifest["binary_sha256"] != sha256(PREPARED / "kunato"):
        raise ValueError("Kunato sources/binary changed; run prepare")
    for image in manifest["images"].values():
        command(["docker", "image", "inspect", image["id"]])
    for name, tool in lock.get("tools", {}).items():
        binary = PREPARED / name
        if not binary.exists() or sha256(binary) != tool["binary_sha256"]:
            raise ValueError(f"Prepared {name} is missing or stale; run prepare")
    fixture = manifest["fixtures"]["httpd_cve_2021_41773"]
    locked_fixture = lock["fixtures"]["httpd_cve_2021_41773"]
    command(["docker", "image", "inspect", fixture["id"]])
    if (tree_hash(ROOT / locked_fixture["build_context"]) != locked_fixture["source_sha256"]
            or sha256(ROOT / locked_fixture["template"]) != locked_fixture["template_sha256"]):
        raise ValueError("Lab fixture or template changed; run prepare")
    if fixture["source_sha256"] != locked_fixture["source_sha256"]:
        raise ValueError("Prepared CVE fixture is stale; run prepare")
    return manifest


def make_config(source, upstream="http://origin:8080", protection=None, timeouts=None):
    # The example has a stable two-level category layout; fail if it changes.
    if source.count("  - name: trusted-sources\n") != 1:
        raise ValueError("Expected one trusted-sources category in the example")
    source, count = re.subn(r"(?ms)^  - name: trusted-sources\n.*?(?=^  - name: |^\S)", "", source, count=1)
    if count != 1:
        raise ValueError("Could not remove trusted-sources")
    source, count = re.subn(r"(?m)^listen: .*", "listen: 0.0.0.0:8080", source)
    if count != 1:
        raise ValueError("Expected one listener")
    source, count = re.subn(r"(?m)^upstream: .*", f"upstream: {upstream}", source)
    if count != 1:
        raise ValueError("Expected one upstream")
    if protection is not None:
        source, count = re.subn(r"(?ms)^protection:\n.*?(?=^\S)", protection, source, count=1)
        if count != 1:
            raise ValueError("Expected one protection block")
    if timeouts is not None:
        source, count = re.subn(r"(?ms)^timeouts:\n(?:  [^\n]*\n)+", timeouts, source, count=1)
        if count != 1:
            raise ValueError("Expected one timeouts block")
    return source


def write_gotestwaf_cases(destination, cases):
    # JSON is a YAML subset accepted by goTestWAF; no Python YAML dependency.
    for case in cases:
        directory = destination / ("attacks" if case["expect"] == "block" else "false-pos")
        directory.mkdir(parents=True, exist_ok=True)
        payload = case.get("body") or unquote_plus(case["target"].partition("?")[2])
        if not payload:
            continue
        has_body = "body" in case
        request = {"method": case["method"], "path": f"/case/{case['id']}" + ("" if has_body else "?{{payload}}"),
                   "headers": case.get("headers", {}), "body": "{{payload}}" if has_body else ""}
        data = {"payload": [payload], "encoder": ["Plain"], "type": "Kunato smoke",
                "placeholder": [{"RawRequest": request}]}
        write_json(directory / (case["id"] + ".yml"), data)


class SandboxSuite:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.input = run_dir / "input"
        self.manifest = json.loads((run_dir / "manifest.json").read_text())
        self.project = self.manifest["project"]
        if self.project != "kunato-lab-" + run_dir.name.lower():
            raise ValueError("Manifest project does not identify this lab run")
        self.env = {**os.environ, "LAB_INPUT": str(self.input),
                    "LAB_PLATFORM": self.manifest["platform"], "LAB_NONCE": "unstarted",
                    "LAB_CONFIG": "rules-origin.yaml",
                    "LAB_DISABLE_PROTECTION": "1",
                    "LAB_DVWA_DISABLE_AUTH": "true",
                    "LAB_PYTHON_IMAGE": self.manifest["images"]["python"]["id"],
                    "LAB_GOTESTWAF_IMAGE": self.manifest["images"]["gotestwaf"]["id"],
                    "LAB_MARIADB_IMAGE": self.manifest["images"]["mariadb"]["id"],
                    "LAB_DVWA_IMAGE": self.manifest["images"]["dvwa"]["id"],
                    "LAB_SQLMAP_IMAGE": self.manifest["images"]["sqlmap"]["id"],
                    "LAB_NUCLEI_IMAGE": self.manifest["images"]["nuclei"]["id"],
                    "LAB_ZAP_IMAGE": self.manifest["images"]["zap"]["id"],
                    "LAB_CRS_IMAGE": self.manifest["images"]["crs"]["id"],
                    "LAB_K6_IMAGE": self.manifest["images"]["k6"]["id"],
                    "LAB_CVE_IMAGE": self.manifest["fixtures"]["httpd_cve_2021_41773"]["id"]}
        self.base = ["docker", "compose", "--project-name", self.project,
                     "--file", str(self.input / "lab/compose.yaml")]

    def compose(self, *args, **kwargs):
        return command([*self.base, *args], env=self.env, **kwargs)

    def probe(self, service, mode, log=None, check=True, extra=()):
        result = self.compose("run", "--rm", "--no-deps", "-T", service, mode, *extra,
                              check=check, log=log)
        if mode in {"cases", "raw"}:
            return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if not result.stdout.strip():
            return {"probe_error": result.stderr[-1000:] or f"probe exited {result.returncode}"}
        try:
            return json.loads(result.stdout)
        except ValueError:
            return {"probe_error": result.stdout[-1000:] or result.stderr[-1000:]
                    or f"probe exited {result.returncode}"}

    def probe_exec(self, service, mode, extra=()):
        result = self.compose("exec", "-T", service, "python3", "-B", "/lab/probe.py",
                              mode, *extra, check=False)
        if not result.stdout.strip():
            return {"probe_error": result.stderr[-1000:] or f"probe exited {result.returncode}"}
        return json.loads(result.stdout)

    def logs(self, phase):
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        for service in ("origin", "kunato"):
            self.compose("logs", "--no-color", "--no-log-prefix", service, log=directory / f"{service}.jsonl")
        self.compose("ps", "--all", "--format", "json", log=directory / "containers.json")
        return read_jsonl(directory / "origin.jsonl"), read_jsonl(directory / "kunato.jsonl")

    def raw_logs(self, phase, service):
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        path = directory / f"{service}.log"
        self.compose("logs", "--no-color", "--no-log-prefix", service, log=path)
        return path.read_text()

    def reset_origin(self, phase, framing="reject", *, config="rules-origin.yaml",
                     disable_protection=True):
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_ORIGIN_FRAMING"] = framing
        self.env["LAB_CONFIG"] = config
        self.env["LAB_DISABLE_PROTECTION"] = "1" if disable_protection else "0"
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "origin", "kunato")
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        for _ in range(50):
            health = self.probe("client", "health", check=False,
                                extra=("--path", "/health", "--status", "200", "--nonce", nonce))
            if health.get("status") == 200 and health.get("origin") == nonce:
                write_json(directory / "health-before.json", health)
                write_json(directory / "attempt.json", {"nonce": nonce, "framing": framing})
                return nonce
            time.sleep(0.2)
        raise RuntimeError("Kunato/origin did not become ready")

    def wait_health(self, phase, service, extra, *, nonce=None, status=200, body=None):
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        health = {}
        for _ in range(50):
            health = self.probe(service, "health", check=False, extra=tuple(extra))
            ok = health.get("status") == status
            if nonce:
                ok = ok and health.get("origin") == nonce
            if body:
                ok = ok and body in health.get("response", "")
            if ok:
                write_json(directory / "health-before.json", health)
                return health
            time.sleep(0.2)
        write_json(directory / "health-before.json", health)
        raise RuntimeError(f"{service} did not become ready for {phase}: {json.dumps(health)}")

    def preflight(self, service, extra=()):
        rendered = json.loads(self.compose("config", "--format", "json").stdout)
        for network in rendered["networks"].values():
            if not network.get("internal"):
                raise ValueError("Lab network has external connectivity")
            actual = command(["docker", "network", "inspect", network["name"]], check=False)
            if actual.returncode == 0 and not json.loads(actual.stdout)[0]["Internal"]:
                raise ValueError("Live Docker network is not internal")
        for service_config in rendered["services"].values():
            if service_config.get("ports") or service_config.get("privileged") or service_config.get("network_mode"):
                raise ValueError("Lab services cannot publish ports or use privileged/host networking")
        write_json(self.run_dir / "compose.json", rendered)
        targets = []
        for name in (service, *extra):
            container_id = self.compose("ps", "-q", name).stdout.strip()
            if not container_id:
                raise ValueError(f"Fixture service {name} is not running")
            container = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
            for network in container["NetworkSettings"]["Networks"].values():
                if network.get("IPAddress"):
                    targets.append((name, network["IPAddress"]))
        isolation_args = []
        for name, address in targets:
            isolation_args += ["--forbidden-host", name, "--forbidden-ip", address]
        isolation = self.probe("client", "isolation", extra=tuple(isolation_args))
        write_json(self.run_dir / "isolation.json", isolation)
        if not isolation.get("isolation_ok"):
            raise ValueError("Network isolation preflight failed")

    def healthy(self, phase, *, path="/health", status=200, nonce=None, body=None,
                service="client", exec=False):
        extra = ("--path", path, "--status", str(status),
                 *(("--nonce", nonce) if nonce else ()))
        health = (self.probe_exec(service, "health", extra=extra) if exec
                  else self.probe(service, "health", extra=extra))
        (self.run_dir / phase).mkdir(parents=True, exist_ok=True)
        write_json(self.run_dir / phase / "health-after.json", health)
        if health.get("status") != status or (body and body not in health.get("response", "")):
            raise ValueError("Normal probe failed after suite")
        if nonce and health.get("origin") != nonce:
            raise ValueError("Normal probe used another origin attempt")
        metrics = self.compose("exec", "-T", "kunato", "python3", "-B", "/lab/probe.py", "metrics")
        (self.run_dir / phase / "metrics.json").write_text(metrics.stdout)
        return health

    def replay(self):
        cases = json.loads((self.input / "lab/cases/smoke.json").read_text())
        control_nonce = self.reset_origin("control")
        self.preflight("origin")
        controls = self.probe("control", "cases", log=self.run_dir / "control/probes.jsonl")
        control_origin, _ = self.logs("control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError("Direct receipt controls failed")
        write_json(self.run_dir / "control/validated.json", controls)
        nonce = self.reset_origin("replay")
        results = self.probe("client", "cases", log=self.run_dir / "replay/probes.jsonl")
        self.healthy("replay", nonce=nonce)
        origin, waf = self.logs("replay")
        verdicts = judge_replay(cases, controls, results, origin, waf, nonce)
        return summarize(verdicts)

    def benign(self):
        cases = json.loads((self.input / "lab/cases/benign.json").read_text())
        control_nonce = self.reset_origin("benign-control")
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/cases/benign.json"),
                              log=self.run_dir / "benign-control/probes.jsonl")
        control_origin, _ = self.logs("benign-control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError("Direct benign controls failed")
        write_json(self.run_dir / "benign-control/validated.json", controls)
        nonce = self.reset_origin("benign")
        results = self.probe("client", "cases",
                             extra=("--cases", "/lab/cases/benign.json"),
                             log=self.run_dir / "benign/probes.jsonl")
        self.healthy("benign", nonce=nonce)
        origin, waf = self.logs("benign")
        return summarize(judge_replay(cases, controls, results, origin, waf, nonce))

    def mutations(self):
        cases = json.loads((self.input / "lab/plans/mutations.json").read_text())
        control_nonce = self.reset_origin("mutations-control")
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/plans/mutations.json"),
                              log=self.run_dir / "mutations-control/probes.jsonl")
        control_origin, _ = self.logs("mutations-control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError("Direct mutation controls failed")
        write_json(self.run_dir / "mutations-control/validated.json", controls)
        nonce = self.reset_origin("mutations")
        results = self.probe("client", "cases",
                             extra=("--cases", "/lab/plans/mutations.json"),
                             log=self.run_dir / "mutations/probes.jsonl")
        self.healthy("mutations", nonce=nonce)
        origin, waf = self.logs("mutations")
        return judge_mutations(cases, controls, results, origin, waf, nonce)

    def protocol(self):
        cases = json.loads((self.input / "lab/plans/protocol.json").read_text())
        controls = []
        direct_origins = {}
        direct_nonces = {}
        for framing in ("reject", "cl", "te"):
            if not any(case.get("direct_framing", "reject") == framing for case in cases):
                continue
            phase = f"protocol-control-{framing}"
            nonce = self.reset_origin(phase, framing=framing)
            self.preflight("origin")
            results = self.probe("control", "raw",
                                 extra=("--cases", f"/lab/plans/protocol-{framing}.json"),
                                 log=self.run_dir / phase / "probes.jsonl")
            origin, _ = self.logs(phase)
            verify_origin(origin, nonce, allow_errors=True)
            controls.extend(results)
            direct_origins[framing] = origin
            direct_nonces[framing] = nonce
        nonce = self.reset_origin("protocol", framing="reject")
        results = self.probe("client", "raw",
                             extra=("--cases", "/lab/plans/protocol.json"),
                             log=self.run_dir / "protocol/probes.jsonl")
        self.healthy("protocol", nonce=nonce)
        origin, _ = self.logs("protocol")
        return judge_protocol(cases, controls, results, direct_origins, origin,
                              direct_nonces, nonce)

    def stats(self):
        container = self.compose("ps", "-q", "kunato").stdout.strip()
        if not container:
            return {}
        result = command(["docker", "stats", "--no-stream", "--format", "json", container],
                         check=False)
        line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        try:
            return json.loads(line) if line else {}
        except ValueError:
            return {}

    def slow(self):
        nonce = self.reset_origin("slow")
        self.preflight("origin")
        before = self.stats()
        slow = self.probe("client", "slow", extra=("--connections", "8", "--hold", "2"))
        normal = self.healthy("slow", nonce=nonce)
        after = self.stats()
        origin, _ = self.logs("slow")
        return judge_slow(slow, normal, before, after)

    def availability(self):
        nonce = self.reset_origin("availability", config="rules-availability.yaml",
                                  disable_protection=False)
        self.preflight("origin")
        before = self.stats()
        slow = self.probe("client", "slow", extra=("--connections", "8", "--hold", "1"))
        time.sleep(0.5)
        slow_body = self.probe("client", "slow-body", extra=("--hold", "3"),
                               check=False)
        time.sleep(0.5)
        slow_read = self.probe("client", "slow-read", extra=("--hold", "2"),
                               check=False)
        time.sleep(0.5)
        exhaustion = self.probe("client", "exhaustion",
                                extra=("--connections", "8"), check=False)
        time.sleep(0.5)
        upstream = self.probe("client", "upstream", check=False)
        normal = self.healthy("availability", nonce=nonce)
        after = self.stats()
        metrics_path = self.run_dir / "availability/metrics.json"
        application_metrics = (json.loads(metrics_path.read_text())
                               if metrics_path.exists() else {"response": ""})
        self.logs("availability")
        return judge_availability(slow, slow_body, slow_read, exhaustion, upstream,
                                  normal, before, after, self.restarts(),
                                  application_metrics)

    def tool_attempt(self, phase, service):
        nonce = self.reset_origin(phase)
        service_name = self.project + "-tool"
        args = ["--url=http://app.test:8080", "--testCasesPath=/lab/plans/gotestwaf",
                "--configPath=/lab/plans/gotestwaf-config.json", "--noEmailReport",
                "--skipWAFIdentification", "--skipWAFBlockCheck", "--workers=1",
                "--randomDelay=1", "--sendDelay=150", "--addDebugHeader",
                "--reportFormat=json", "--reportPath=/reports", "--reportName=result",
                "--passStatusCodes=200", "--blockStatusCodes=403"]
        self.compose("run", "-d", "--no-deps", "--name", service_name,
                     service, *args)
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                result = command(["docker", "exec", service_name, "cat", "/reports/exit-code"],
                                 check=False, quiet=True)
                if result.returncode == 0:
                    break
                running = command(["docker", "inspect", "--format", "{{.State.Running}}", service_name], quiet=True)
                if running.stdout.strip() != "true":
                    raise ValueError("Tool container exited before recording its status")
                time.sleep(0.2)
            else:
                raise ValueError("goTestWAF exceeded the suite deadline")
            command(["docker", "logs", service_name], log=self.run_dir / phase / "tool.log")
            (self.run_dir / phase / "tool-exit-code.txt").write_text(result.stdout)
            if result.stdout.strip() != "0":
                raise ValueError("goTestWAF failed; inspect tool.log")
            command(["docker", "exec", service_name, "cat", "/reports/result.json"],
                    log=self.run_dir / phase / "result.json")
        finally:
            command(["docker", "rm", "--force", "--volumes", service_name], check=False)
        self.healthy(phase, nonce=nonce)
        origin, waf = self.logs(phase)
        report = json.loads((self.run_dir / phase / "result.json").read_text())
        return nonce, origin, waf, report

    def gotestwaf(self):
        nonce, origin, _, report = self.tool_attempt("gotestwaf-control", "gotestwaf-control")
        planned = {path.stem: ("allow" if path.parent.name == "false-pos" else "block")
                   for path in (self.input / "lab/plans/gotestwaf").glob("*/*.yml")}
        controls = judge_gotestwaf(report, origin, [], nonce, planned, control=True)
        if not all(case["verdict"] == "passed" for case in controls):
            raise ValueError("goTestWAF direct receipt controls failed")
        cases = json.loads((self.input / "lab/cases/smoke.json").read_text())
        for case in cases:
            if case["id"] not in planned:
                continue
            observed = [event for event in origin if event.get("event") == "completed"
                        and urlsplit(event.get("target", "")).path == f"/case/{case['id']}"]
            if len(observed) != 1 or observed[0]["method"] != case["method"]:
                raise ValueError("goTestWAF changed the case method or execution count")
            if observed[0]["body_sha256"] != hashlib.sha256(case.get("body", "").encode()).hexdigest():
                raise ValueError("goTestWAF changed the case body")
            if parse_qsl(urlsplit(observed[0]["target"]).query, keep_blank_values=True) != parse_qsl(
                    urlsplit(case["target"]).query, keep_blank_values=True):
                raise ValueError("goTestWAF changed decoded query parameters")
        nonce, origin, waf, report = self.tool_attempt("gotestwaf", "gotestwaf")
        return summarize(judge_gotestwaf(report, origin, waf, nonce, planned))

    def reset_dvwa(self, phase, *, config="rules-dvwa.yaml", disable_protection=True,
                   auth_disabled=True):
        self.compose("rm", "-s", "-f", "-v", "cve", check=False)
        self.compose("rm", "-s", "-f", "-v", "db", "dvwa", check=False)
        self.env["LAB_DVWA_DISABLE_AUTH"] = "true" if auth_disabled else "false"
        self.env["LAB_DISABLE_PROTECTION"] = "1" if disable_protection else "0"
        self.compose("up", "-d", "--wait", "--wait-timeout", "120", "db", "dvwa")
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        bootstrap_args = ["setup", "--base", "http://dvwa", "--timeout", "60"]
        if not auth_disabled:
            bootstrap_args.append("--auth")
        self.compose("run", "--rm", "--no-deps", "-T", "bootstrap", *bootstrap_args,
                     log=directory / "bootstrap.json")
        bootstrap = json.loads((directory / "bootstrap.json").read_text())
        if bootstrap.get("status") != "ok":
            raise ValueError("DVWA bootstrap failed")
        sql = ("DROP TABLE IF EXISTS lab_canary; "
               "CREATE TABLE lab_canary (id INT PRIMARY KEY, secret VARCHAR(64)); "
               f"INSERT INTO lab_canary VALUES (1, 'CANARY-{nonce}');")
        self.compose("exec", "-T", "-e", "MYSQL_PWD=p@ssw0rd", "db",
                     "mariadb", "-udvwa", "dvwa", "-e", sql)
        self.env["LAB_CONFIG"] = config
        self.compose("up", "-d", "--force-recreate", "kunato")
        health_path = ("/vulnerabilities/sqli/?id=1&Submit=Submit"
                       if auth_disabled else "/login.php")
        self.wait_health(phase, "client", ("--path", health_path, "--status", "200"))
        write_json(directory / "attempt.json", {"nonce": nonce})
        return nonce

    def sqlmap(self):
        self.compose("stop", "origin", check=False)
        control_nonce = self.reset_dvwa("sqlmap-control")
        self.preflight("dvwa", ("db",))
        self.tool("sqlmap-control", "sqlmap-control",
                  self.sqlmap_args("http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"),
                  "sqlmap.log", 180)
        self.healthy("sqlmap-control", path="/vulnerabilities/sqli/?id=1&Submit=Submit", body="First name")
        control_output = (self.run_dir / "sqlmap-control/sqlmap.log").read_text()
        control_access = self.raw_logs("sqlmap-control", "dvwa")
        nonce = self.reset_dvwa("sqlmap")
        self.preflight("dvwa", ("db",))
        self.tool("sqlmap", "sqlmap",
                  self.sqlmap_args("http://app.test:8080/vulnerabilities/sqli/?id=1&Submit=Submit"),
                  "sqlmap.log", 180)
        self.healthy("sqlmap", path="/vulnerabilities/sqli/?id=1&Submit=Submit", body="First name")
        protected_output = (self.run_dir / "sqlmap/sqlmap.log").read_text()
        protected_access = self.raw_logs("sqlmap", "dvwa")
        _, waf = self.logs("sqlmap")
        return judge_sqlmap(control_output, protected_output, control_access, protected_access,
                            waf, nonce, control_nonce)

    @staticmethod
    def sqlmap_args(url):
        return ["-u", url, "--batch", "--level=1", "--risk=1", "--technique=U",
                "--dump", "-T", "lab_canary", "--flush-session", "--disable-coloring",
                "--user-agent", USER_AGENT, "--output-dir=/tmp/sqlmap"]

    def reset_cve(self, phase):
        self.compose("rm", "-s", "-f", "-v", "db", "dvwa", check=False)
        self.compose("rm", "-s", "-f", "cve", check=False)
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_DISABLE_PROTECTION"] = "1"
        self.compose("up", "-d", "--force-recreate", "cve")
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        self.wait_health(phase, "control",
                         ("--host", "cve", "--port", "80", "--path", "/", "--status", "200"))
        self.env["LAB_CONFIG"] = "rules-cve.yaml"
        self.compose("up", "-d", "--force-recreate", "kunato")
        self.wait_health(phase, "client", ("--path", "/", "--status", "200"))
        write_json(directory / "attempt.json", {"nonce": nonce})
        return nonce

    @staticmethod
    def nuclei_args(target, nonce):
        return ["-u", target, "-t", "/lab/templates/cve-2021-41773-canary.yaml",
                "-var", f"canary=kunato-lab-canary-{nonce}",
                "-var", f"user_agent={USER_AGENT}",
                "-jsonl", "-include-rr", "-o", "/reports/nuclei.jsonl",
                "-duc", "-ni", "-no-color", "-timeout", "5", "-retries", "0"]

    @staticmethod
    def read_results(phase):
        path = phase / "nuclei.jsonl"
        return path.read_text() if path.exists() else ""

    def nuclei(self):
        control_nonce = self.reset_cve("nuclei-control")
        self.preflight("cve")
        self.tool_detached("nuclei-control", "nuclei-control",
                           self.nuclei_args("http://cve:80", control_nonce), "nuclei.log", 120)
        self.healthy("nuclei-control", path="/", body="It works!")
        control_results = self.read_results(self.run_dir / "nuclei-control")
        control_access = self.raw_logs("nuclei-control", "cve")
        nonce = self.reset_cve("nuclei")
        self.preflight("cve")
        self.tool_detached("nuclei", "nuclei",
                           self.nuclei_args("http://app.test:8080", nonce), "nuclei.log", 120)
        self.healthy("nuclei", path="/", body="It works!")
        protected_results = self.read_results(self.run_dir / "nuclei")
        protected_access = self.raw_logs("nuclei", "cve")
        _, waf = self.logs("nuclei")
        return judge_nuclei(control_results, protected_results, control_access, protected_access,
                            waf, nonce, control_nonce)

    @staticmethod
    def ffuf_args(target, host=None):
        args = ["-u", f"{target}/FUZZ", "-w", "/lab/plans/ffuf-paths.txt"]
        if host:
            args += ["-H", f"Host: {host}"]
        args += ["-H", f"User-Agent: {USER_AGENT}", "-mc", "all",
                 "-of", "json", "-o", "/reports/ffuf.json",
                 "-t", "2", "-rate", "10", "-p", "0.02", "-s",
                 "-timeout", "5", "-maxtime", "60"]
        return args

    def read_ffuf(self, phase):
        path = self.run_dir / phase / "ffuf.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def ffuf(self):
        self.compose("stop", "origin", check=False)
        cases = json.loads((self.input / "lab/cases/ffuf.json").read_text())
        self.compose("up", "-d", "normal")
        self.reset_dvwa("ffuf-control")
        self.preflight("dvwa", ("db",))
        self.tool_detached("ffuf-control", "ffuf-control",
                           self.ffuf_args("http://dvwa", host="app.test:8080"),
                           "ffuf.log", 120, result="ffuf.json")
        self.healthy("ffuf-control", path="/index.php", service="normal", exec=True)
        control_report = self.read_ffuf("ffuf-control")
        control_access = self.raw_logs("ffuf-control", "dvwa")
        self.reset_dvwa("ffuf")
        self.preflight("dvwa", ("db",))
        self.tool_detached("ffuf", "ffuf", self.ffuf_args("http://app.test:8080"),
                           "ffuf.log", 120, result="ffuf.json")
        self.healthy("ffuf", path="/index.php", service="normal", exec=True)
        protected_report = self.read_ffuf("ffuf")
        protected_access = self.raw_logs("ffuf", "dvwa")
        _, waf = self.logs("ffuf")
        discovery = judge_ffuf(control_report, protected_report, control_access,
                               protected_access, waf, cases)
        self.reset_dvwa("ffuf-behavior", config="rules-ffuf.yaml", disable_protection=False)
        self.preflight("dvwa", ("db",))
        self.tool_detached("ffuf-behavior", "ffuf", self.ffuf_args("http://app.test:8080"),
                           "ffuf.log", 120, result="ffuf.json")
        normal_health = self.healthy("ffuf-behavior", path="/index.php",
                                     service="normal", exec=True)
        behavior_report = self.read_ffuf("ffuf-behavior")
        behavior_access = self.raw_logs("ffuf-behavior", "dvwa")
        _, behavior_waf = self.logs("ffuf-behavior")
        behavior = judge_ffuf_behavior(behavior_report, behavior_access, behavior_waf,
                                       normal_health)
        result = summarize(discovery["cases"] + behavior["cases"])
        result["notes"] = {"discovery": discovery["notes"], "behavior": behavior["notes"]}
        return result

    def read_zap(self, phase):
        path = self.run_dir / phase / "zap.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def zap(self):
        self.compose("stop", "origin", check=False)
        self.compose("up", "-d", "normal")
        self.reset_dvwa("zap-control", auth_disabled=False)
        self.preflight("dvwa", ("db",))
        self.tool_detached("zap-control", "zap-control",
                           ["/lab/plans/zap-control.yaml"], "zap.log", 480,
                           result="zap.json")
        self.healthy("zap-control", path="/login.php", service="normal", exec=True)
        control_log = (self.run_dir / "zap-control/zap.log").read_text()
        control_report = self.read_zap("zap-control")
        control_access = self.raw_logs("zap-control", "dvwa")
        self.reset_dvwa("zap", auth_disabled=False)
        self.preflight("dvwa", ("db",))
        self.tool_detached("zap", "zap", ["/lab/plans/zap.yaml"], "zap.log", 480,
                           result="zap.json")
        self.healthy("zap", path="/login.php", service="normal", exec=True)
        protected_log = (self.run_dir / "zap/zap.log").read_text()
        protected_report = self.read_zap("zap")
        protected_access = self.raw_logs("zap", "dvwa")
        _, waf = self.logs("zap")
        return judge_zap_workflow(control_log, protected_log, control_report,
                                  protected_report, control_access, protected_access, waf)

    def crs(self):
        cases = json.loads((self.input / "lab/plans/mutations.json").read_text())
        control_nonce = self.reset_origin("crs-control")
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/plans/mutations.json"),
                              log=self.run_dir / "crs-control/probes.jsonl")
        control_origin, _ = self.logs("crs-control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError("Direct CRS-comparison controls failed")
        write_json(self.run_dir / "crs-control/validated.json", controls)
        kunato_nonce = self.reset_origin("crs-kunato")
        kunato_results = self.probe("client", "cases",
                                    extra=("--cases", "/lab/plans/mutations.json"),
                                    log=self.run_dir / "crs-kunato/probes.jsonl")
        self.healthy("crs-kunato", nonce=kunato_nonce)
        kunato_origin, kunato_waf = self.logs("crs-kunato")
        kunato_verdicts = judge_replay(cases, controls, kunato_results, kunato_origin,
                                       kunato_waf, kunato_nonce)
        crs_nonce = self.reset_origin("crs")
        self.compose("up", "-d", "crs")
        self.wait_health("crs", "client",
                         ("--host", "crs", "--port", "8080", "--path", "/health",
                          "--status", "200"), nonce=crs_nonce)
        crs_results = self.probe("client", "cases",
                                 extra=("--cases", "/lab/plans/mutations.json",
                                        "--host", "crs", "--port", "8080"),
                                 log=self.run_dir / "crs/probes.jsonl")
        crs_origin, _ = self.logs("crs")
        self.raw_logs("crs", "crs")
        self.compose("rm", "-s", "-f", "crs", check=False)
        return judge_crs(cases, crs_results, kunato_verdicts, crs_origin, crs_nonce)

    def tool(self, phase, service, args, name, timeout):
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        result = self.compose("run", "--rm", "--no-deps", "-T", service, *args,
                              check=False, timeout=timeout, log=directory / name)
        (directory / (name + ".exit-code")).write_text(str(result.returncode))
        if result.returncode:
            raise RuntimeError(f"{service} exited {result.returncode}; inspect {directory / name}")
        return result

    def start_tool(self, phase, service, args, name):
        (self.run_dir / phase).mkdir(exist_ok=True)
        # Detached tools block reading stdin when Compose leaves it open; the
        # runners have no interactive input.
        self.compose("run", "-d", "-T", "--interactive=false", "--no-deps",
                     "--name", self.project + "-" + service, service, *args)

    def finish_tool(self, phase, service, name, timeout, result):
        directory = self.run_dir / phase
        service_name = self.project + "-" + service

        def collect():
            command(["docker", "logs", service_name], check=False, log=directory / name)
            command(["docker", "exec", service_name, "cat", f"/reports/{result}"],
                    check=False, log=directory / result)

        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                exit_status = command(["docker", "exec", service_name, "cat", "/reports/exit-code"],
                                      check=False, quiet=True)
                if exit_status.returncode == 0:
                    break
                running = command(["docker", "inspect", "--format", "{{.State.Running}}", service_name],
                                  quiet=True)
                if running.stdout.strip() != "true":
                    collect()
                    raise ValueError("Tool container exited before recording its status")
                time.sleep(0.2)
            else:
                collect()
                raise ValueError(f"{service} exceeded the suite deadline")
            collect()
            (directory / (name + ".exit-code")).write_text(exit_status.stdout)
            if exit_status.stdout.strip() != "0":
                raise ValueError(f"{service} failed; inspect {directory / name}")
        finally:
            command(["docker", "rm", "--force", "--volumes", service_name], check=False)

    def tool_detached(self, phase, service, args, name, timeout, result="nuclei.jsonl"):
        self.start_tool(phase, service, args, name)
        self.finish_tool(phase, service, name, timeout, result)

    def restarts(self):
        result = command(["docker", "inspect", "--format", "{{.RestartCount}}",
                          self.project + "-kunato"], check=False)
        try:
            return int(result.stdout.strip())
        except ValueError:
            return 0

    def load(self):
        nonce = self.reset_origin("load")
        self.preflight("origin")
        before = self.stats()
        self.start_tool("load", "load", [], "k6")
        try:
            time.sleep(2)
            slow = self.probe("client", "slow", extra=("--connections", "8", "--hold", "2"))
            normal = self.healthy("load", nonce=nonce)
            mid = self.stats()
        finally:
            self.finish_tool("load", "load", "k6", 240, "k6-summary.json")
        summary = json.loads((self.run_dir / "load/k6-summary.json").read_text())
        after = self.stats()
        recovery = self.healthy("load-recovery", nonce=nonce)
        metrics_path = self.run_dir / "load-recovery/metrics.json"
        application_metrics = (json.loads(metrics_path.read_text())
                               if metrics_path.exists() else {"response": ""})
        self.logs("load")
        return judge_load(summary, slow, normal, recovery, before, mid, after,
                          self.restarts(), application_metrics)

    def cleanup(self):
        self.compose("rm", "-s", "-f", "-v", "normal", check=False)
        self.compose("down", "--volumes", "--remove-orphans")
        remaining = {}
        for resource, arguments in (("containers", ["ps", "-aq"]), ("networks", ["network", "ls", "-q"]),
                                    ("volumes", ["volume", "ls", "-q"])):
            result = command(["docker", *arguments, "--filter", f"label=com.docker.compose.project={self.project}"])
            remaining[resource] = result.stdout.split()
        write_json(self.run_dir / "cleanup.json", remaining)
        if any(remaining.values()):
            raise ValueError("Lab resources remain after cleanup")


def new_run(suite):
    manifest = prepared_inputs()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    directory = WORK / run_id
    input_dir = directory / "input"
    input_dir.mkdir(parents=True)
    shutil.copytree(LAB, input_dir / "lab", ignore=shutil.ignore_patterns("__pycache__", "tests"))
    shutil.copy2(PREPARED / "kunato", input_dir / "kunato")
    shutil.copy2(PREPARED / "ffuf", input_dir / "ffuf")
    config_dir = input_dir / "config"
    config_dir.mkdir()
    original = (ROOT / "rules.example.yaml").read_text()
    (config_dir / "rules.example.yaml").write_text(original)
    for name, upstream in (("rules-origin.yaml", "http://origin:8080"),
                           ("rules-dvwa.yaml", "http://dvwa:80"),
                           ("rules-cve.yaml", "http://cve:80")):
        (config_dir / name).write_text(make_config(original, upstream))
    (config_dir / "rules-ffuf.yaml").write_text(
        make_config(original, "http://dvwa:80", FFUF_PROTECTION))
    (config_dir / "rules-availability.yaml").write_text(
        make_config(original, "http://origin:8080", AVAILABILITY_PROTECTION,
                    timeouts=AVAILABILITY_TIMEOUTS))
    zap_template = (LAB / "templates/zap-authenticated.yaml").read_text()
    cases = json.loads((LAB / "cases/smoke.json").read_text())
    validate_cases(cases)
    validate_cases(json.loads((LAB / "cases/benign.json").read_text()))
    ffuf_cases = json.loads((LAB / "cases/ffuf.json").read_text())
    validate_ffuf_cases(ffuf_cases)
    mutation_cases = json.loads((LAB / "cases/mutations.json").read_text())
    validate_mutations(mutation_cases)
    protocol_cases = json.loads((LAB / "cases/protocol.json").read_text())
    validate_protocol(protocol_cases)
    plans = input_dir / "lab/plans"
    plans.mkdir(exist_ok=True)
    write_gotestwaf_cases(plans / "gotestwaf", cases)
    write_json(plans / "gotestwaf-config.json", {"headers": {"User-Agent": USER_AGENT}})
    (plans / "ffuf-paths.txt").write_text(
        "\n".join(case["path"].lstrip("/") for case in ffuf_cases) + "\n")
    (plans / "zap-control.yaml").write_text(
        zap_template.replace("__TARGET__", "http://dvwa"))
    (plans / "zap.yaml").write_text(
        zap_template.replace("__TARGET__", "http://app.test:8080"))
    write_json(plans / "mutations.json", mutation_cases)
    write_json(plans / "protocol.json", protocol_cases)
    for framing in ("reject", "cl", "te"):
        write_json(plans / f"protocol-{framing}.json",
                   [case for case in protocol_cases
                    if case.get("direct_framing", "reject") == framing])
    hashes = {str(path.relative_to(input_dir)): sha256(path) for path in sorted(input_dir.rglob("*")) if path.is_file()}
    manifest.update(run_id=run_id, project="kunato-lab-" + run_id.lower(), suite=suite,
                    commit=command(["git", "rev-parse", "HEAD"]).stdout.strip(), inputs=hashes)
    write_json(directory / "manifest.json", manifest)
    print(f"Run artifacts: {directory}", flush=True)
    return directory


def run(suite):
    global COMMAND_JOURNAL
    directory = new_run(suite)
    COMMAND_JOURNAL = directory / "commands.jsonl"
    lab = SandboxSuite(directory)
    report = {"run_id": directory.name, "passed": False, "suites": {}}
    try:
        lab.compose("config", "--quiet")
        for name in ("rules-origin.yaml", "rules-dvwa.yaml", "rules-cve.yaml",
                     "rules-ffuf.yaml", "rules-availability.yaml"):
            lab.compose("run", "--rm", "--no-deps", "-T", "kunato",
                        "--config", f"/config/{name}", "--validate")
        report["suites"]["replay"] = lab.replay()
        if suite in {"benign", "all"}:
            report["suites"]["benign"] = lab.benign()
        if suite in {"mutations", "all"}:
            report["suites"]["mutations"] = lab.mutations()
        if suite in {"protocol", "all"}:
            report["suites"]["protocol"] = lab.protocol()
        if suite in {"slow", "all"}:
            report["suites"]["slow"] = lab.slow()
        if suite in {"availability", "all"}:
            report["suites"]["availability"] = lab.availability()
        if suite in {"load", "all"}:
            report["suites"]["load"] = lab.load()
        if suite in {"gotestwaf", "all"}:
            report["suites"]["gotestwaf"] = lab.gotestwaf()
        if suite in {"sqlmap", "all"}:
            report["suites"]["sqlmap"] = lab.sqlmap()
        if suite in {"nuclei", "all"}:
            report["suites"]["nuclei"] = lab.nuclei()
        if suite in {"ffuf", "all"}:
            report["suites"]["ffuf"] = lab.ffuf()
        if suite in {"zap", "all"}:
            report["suites"]["zap"] = lab.zap()
        if suite == "crs":
            report["suites"]["crs"] = lab.crs()
        report["passed"] = all(result["passed"] for result in report["suites"].values())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, TypeError) as error:
        report["error"] = str(error)
        try:
            lab.logs("failure")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as diagnostic_error:
            report["diagnostic_error"] = str(diagnostic_error)
        for service in ("dvwa", "cve", "db"):
            try:
                lab.raw_logs("failure", service)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                pass
    finally:
        try:
            lab.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as cleanup_error:
            report["passed"] = False
            report["cleanup_error"] = str(cleanup_error)
        write_json(directory / "report.json", report)
        render_report(directory)
    return int(not report["passed"])


def render_report(directory):
    report = json.loads((directory / "report.json").read_text())
    lines = ["# Local security lab report", "", f"Run: `{report['run_id']}`", "",
             f"Result: {'PASS' if report['passed'] else 'FAIL'}", ""]
    suites = report.get("suites", report.get("campaigns", {}))
    for name, result in suites.items():
        lines += [f"## {name}", "", "| Case | Expectation | Verdict | Origin receipts |",
                  "| --- | --- | --- | --- |"]
        lines += [f"| {case['id']} | {case['expect']} | {case['verdict']} | {case['origin_receipts']} |"
                  for case in result["cases"]]
        lines += ["", "Counts: " + json.dumps(result["counts"])]
        if "notes" in result:
            lines += ["", "Notes: `" + json.dumps(result["notes"], sort_keys=True) + "`"]
        lines += [""]
    for field in ("error", "diagnostic_error", "cleanup_error"):
        if field in report:
            lines += [f"{field}: `{report[field]}`", ""]
    (directory / "report.md").write_text("\n".join(lines))
    print("\n".join(lines), flush=True)
    print(f"Evidence: {directory}", flush=True)
    return report["passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    subs.add_parser("prepare", help="Pull frozen images, download tools, build the CVE fixture, and build the local Kunato revision")
    subs.add_parser("verify", help="Check prepared inputs without downloads")
    runner = subs.add_parser("run", help="Run the isolated regression sandbox suites")
    runner.add_argument("--sandbox-suite", "--suite", "--campaign", dest="suite",
                        choices=["replay", "benign", "mutations", "protocol", "gotestwaf",
                                 "sqlmap", "nuclei", "ffuf", "zap", "crs", "slow",
                                 "availability", "load", "all"],
                        default="replay")
    for operation in ("report", "down"):
        sub = subs.add_parser(operation)
        sub.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare()
        elif args.operation == "verify":
            prepared_inputs()
            print("Prepared inputs verified")
        elif args.operation == "run":
            return run(args.suite)
        else:
            directory = args.run_directory.resolve()
            if directory.parent != WORK or not re.fullmatch(r"[0-9]{8}T[0-9]{6}-[a-f0-9]{8}", directory.name):
                raise ValueError("Expected an existing run directory under target/security-lab")
            if args.operation == "report":
                return int(not render_report(directory))
            else:
                SandboxSuite(directory).cleanup()
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, TypeError) as error:
        print(f"security-lab: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
