"""Prepare frozen inputs and run isolated, observable local WAF campaigns."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from evidence import (judge_gotestwaf, judge_replay, origin_response, read_jsonl,
                      summarize, validate_cases, verify_origin, USER_AGENT)

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
WORK = ROOT / "target/security-lab"
PREPARED = WORK / "prepared"
COMMAND_JOURNAL = None


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def source_hash():
    digest = hashlib.sha256()
    for path in sorted([ROOT / "Cargo.toml", ROOT / "Cargo.lock", *ROOT.glob("src/**/*.rs")]):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


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
    PREPARED.mkdir(parents=True, exist_ok=True)
    command(["docker", "version", "--format", "{{.Server.Version}}"])
    images = {}
    for name, reference in lock["images"].items():
        inspected = command(["docker", "image", "inspect", reference], check=False)
        if inspected.returncode:
            command(["docker", "pull", "--platform", lock["platform"], reference], timeout=600)
            inspected = command(["docker", "image", "inspect", reference])
        image = json.loads(inspected.stdout)[0]
        images[name] = {"reference": reference, "id": image["Id"],
                        "digests": image.get("RepoDigests", []), "architecture": image["Architecture"]}
        if image["Architecture"] != lock["platform"].split("/")[1]:
            raise ValueError("Prepared image does not match the selected platform")
    source_before = source_hash()
    command(["cargo", "build", "--release", "--locked"], timeout=600)
    if source_hash() != source_before:
        raise ValueError("Rust sources changed during the build; repeat prepare")
    shutil.copy2(ROOT / "target/release/kunato", PREPARED / "kunato")
    manifest = {"schema_version": 1, "platform": lock["platform"], "images": images,
                "tool_versions": lock["tool_versions"],
                "binary_sha256": sha256(PREPARED / "kunato"), "source_sha256": source_hash(),
                "lock_sha256": sha256(LAB / "artifacts.lock.json")}
    write_json(PREPARED / "manifest.json", manifest)
    print(f"Prepared inputs: {PREPARED}")


def prepared_inputs():
    manifest = json.loads((PREPARED / "manifest.json").read_text())
    if manifest["lock_sha256"] != sha256(LAB / "artifacts.lock.json"):
        raise ValueError("Image lock changed; run prepare")
    if manifest["source_sha256"] != source_hash() or manifest["binary_sha256"] != sha256(PREPARED / "kunato"):
        raise ValueError("Kunato sources/binary changed; run prepare")
    for image in manifest["images"].values():
        command(["docker", "image", "inspect", image["id"]])
    return manifest


def make_config(source):
    # The example has a stable two-level category layout; fail if it changes.
    if source.count("  - name: trusted-sources\n") != 1:
        raise ValueError("Expected one trusted-sources category in the example")
    source, count = re.subn(r"(?ms)^  - name: trusted-sources\n.*?(?=^  - name: |^\S)", "", source, count=1)
    if count != 1:
        raise ValueError("Could not remove trusted-sources")
    source, count = re.subn(r"(?m)^listen: .*", "listen: 0.0.0.0:8080", source)
    if count != 1:
        raise ValueError("Expected one listener")
    source, count = re.subn(r"(?m)^upstream: .*", "upstream: http://origin:8080", source)
    if count != 1:
        raise ValueError("Expected one upstream")
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


class Campaign:
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.input = run_dir / "input"
        self.manifest = json.loads((run_dir / "manifest.json").read_text())
        self.project = self.manifest["project"]
        if self.project != "kunato-lab-" + run_dir.name.lower():
            raise ValueError("Manifest project does not identify this lab run")
        self.env = {**os.environ, "LAB_INPUT": str(self.input),
                    "LAB_PLATFORM": self.manifest["platform"], "LAB_NONCE": "unstarted",
                    "LAB_PYTHON_IMAGE": self.manifest["images"]["python"]["id"],
                    "LAB_GOTESTWAF_IMAGE": self.manifest["images"]["gotestwaf"]["id"]}
        self.base = ["docker", "compose", "--project-name", self.project,
                     "--file", str(self.input / "lab/compose.yaml")]

    def compose(self, *args, **kwargs):
        return command([*self.base, *args], env=self.env, **kwargs)

    def probe(self, service, mode, log=None, check=True, extra=()):
        result = self.compose("run", "--rm", "--no-deps", service, mode, *extra,
                              check=check, log=log)
        if mode == "cases":
            return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def logs(self, phase):
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        for service in ("origin", "kunato"):
            self.compose("logs", "--no-color", "--no-log-prefix", service, log=directory / f"{service}.jsonl")
        self.compose("ps", "--all", "--format", "json", log=directory / "containers.json")
        return read_jsonl(directory / "origin.jsonl"), read_jsonl(directory / "kunato.jsonl")

    def reset(self, phase):
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "origin", "kunato")
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        for _ in range(20):
            health = self.probe("client", "health", check=False)
            if health.get("origin") == nonce and health.get("status") == 200:
                write_json(directory / "health-before.json", health)
                write_json(directory / "attempt.json", {"nonce": nonce})
                return nonce
            time.sleep(0.2)
        raise RuntimeError("Kunato/origin did not become ready")

    def preflight(self):
        rendered = json.loads(self.compose("config", "--format", "json").stdout)
        for network in rendered["networks"].values():
            if not network.get("internal"):
                raise ValueError("Lab network has external connectivity")
            actual = json.loads(command(["docker", "network", "inspect", network["name"]]).stdout)[0]
            if not actual["Internal"]:
                raise ValueError("Live Docker network is not internal")
        for service in rendered["services"].values():
            if service.get("ports") or service.get("privileged") or service.get("network_mode"):
                raise ValueError("Lab services cannot publish ports or use privileged/host networking")
        write_json(self.run_dir / "compose.json", rendered)
        origin_id = self.compose("ps", "-q", "origin").stdout.strip()
        origin = json.loads(command(["docker", "inspect", origin_id]).stdout)[0]
        origin_ip = origin["NetworkSettings"]["Networks"][self.project + "_back"]["IPAddress"]
        isolation = self.probe("client", "isolation", extra=("--origin-ip", origin_ip))
        write_json(self.run_dir / "isolation.json", isolation)
        if not isolation.get("isolation_ok"):
            raise ValueError("Network isolation preflight failed")

    def healthy(self, phase, nonce):
        health = self.probe("client", "health")
        write_json(self.run_dir / phase / "health-after.json", health)
        if health.get("origin") != nonce or health.get("status") != 200:
            raise ValueError("Normal probe failed after campaign")
        metrics = self.compose("exec", "-T", "kunato", "python3", "-B", "/lab/probe.py", "metrics")
        (self.run_dir / phase / "metrics.json").write_text(metrics.stdout)

    def replay(self):
        cases = json.loads((self.input / "lab/cases/smoke.json").read_text())
        control_nonce = self.reset("control")
        self.preflight()
        controls = self.probe("control", "cases", log=self.run_dir / "control/probes.jsonl")
        control_origin, _ = self.logs("control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError("Direct receipt controls failed")
        write_json(self.run_dir / "control/validated.json", controls)
        nonce = self.reset("replay")
        results = self.probe("client", "cases", log=self.run_dir / "replay/probes.jsonl")
        self.healthy("replay", nonce)
        origin, waf = self.logs("replay")
        verdicts = judge_replay(cases, controls, results, origin, waf, nonce)
        return summarize(verdicts)

    def tool_attempt(self, phase, service):
        nonce = self.reset(phase)
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
                raise ValueError("goTestWAF exceeded the campaign deadline")
            command(["docker", "logs", service_name], log=self.run_dir / phase / "tool.log")
            (self.run_dir / phase / "tool-exit-code.txt").write_text(result.stdout)
            if result.stdout.strip() != "0":
                raise ValueError("goTestWAF failed; inspect tool.log")
            command(["docker", "exec", service_name, "cat", "/reports/result.json"],
                    log=self.run_dir / phase / "result.json")
        finally:
            command(["docker", "rm", "--force", "--volumes", service_name], check=False)
        self.healthy(phase, nonce)
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

    def cleanup(self):
        self.compose("down", "--volumes", "--remove-orphans")
        remaining = {}
        for resource, arguments in (("containers", ["ps", "-aq"]), ("networks", ["network", "ls", "-q"]),
                                    ("volumes", ["volume", "ls", "-q"])):
            result = command(["docker", *arguments, "--filter", f"label=com.docker.compose.project={self.project}"])
            remaining[resource] = result.stdout.split()
        write_json(self.run_dir / "cleanup.json", remaining)
        if any(remaining.values()):
            raise ValueError("Lab resources remain after cleanup")


def new_run(campaign):
    manifest = prepared_inputs()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    directory = WORK / run_id
    input_dir = directory / "input"
    input_dir.mkdir(parents=True)
    shutil.copytree(LAB, input_dir / "lab", ignore=shutil.ignore_patterns("__pycache__", "tests"))
    shutil.copy2(PREPARED / "kunato", input_dir / "kunato")
    config_dir = input_dir / "config"
    config_dir.mkdir()
    original = (ROOT / "rules.example.yaml").read_text()
    (config_dir / "rules.example.yaml").write_text(original)
    (config_dir / "rules.yaml").write_text(make_config(original))
    cases = json.loads((LAB / "cases/smoke.json").read_text())
    validate_cases(cases)
    plans = input_dir / "lab/plans"
    plans.mkdir(exist_ok=True)
    write_gotestwaf_cases(plans / "gotestwaf", cases)
    write_json(plans / "gotestwaf-config.json", {"headers": {"User-Agent": USER_AGENT}})
    hashes = {str(path.relative_to(input_dir)): sha256(path) for path in sorted(input_dir.rglob("*")) if path.is_file()}
    manifest.update(run_id=run_id, project="kunato-lab-" + run_id.lower(), campaign=campaign,
                    commit=command(["git", "rev-parse", "HEAD"]).stdout.strip(), inputs=hashes)
    write_json(directory / "manifest.json", manifest)
    print(f"Run artifacts: {directory}", flush=True)
    return directory


def run(campaign):
    global COMMAND_JOURNAL
    directory = new_run(campaign)
    COMMAND_JOURNAL = directory / "commands.jsonl"
    lab = Campaign(directory)
    report = {"run_id": directory.name, "passed": False, "campaigns": {}}
    try:
        lab.compose("config", "--quiet")
        lab.compose("run", "--rm", "--no-deps", "kunato",
                    "--config", "/config/rules.yaml", "--validate")
        report["campaigns"]["replay"] = lab.replay()
        if campaign in {"gotestwaf", "all"}:
            report["campaigns"]["gotestwaf"] = lab.gotestwaf()
        report["passed"] = all(result["passed"] for result in report["campaigns"].values())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        try:
            lab.logs("failure")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as diagnostic_error:
            report["diagnostic_error"] = str(diagnostic_error)
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
    for name, result in report["campaigns"].items():
        lines += [f"## {name}", "", "| Case | Expectation | Verdict | Origin receipts |",
                  "| --- | --- | --- | --- |"]
        lines += [f"| {case['id']} | {case['expect']} | {case['verdict']} | {case['origin_receipts']} |"
                  for case in result["cases"]]
        lines += ["", "Counts: " + json.dumps(result["counts"]), ""]
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
    subs.add_parser("prepare", help="Pull frozen images and build the local Kunato revision")
    subs.add_parser("verify", help="Check prepared inputs without downloads")
    runner = subs.add_parser("run", help="Run the isolated receipt-regression campaign")
    runner.add_argument("--campaign", choices=["replay", "gotestwaf", "all"], default="replay")
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
            return run(args.campaign)
        else:
            directory = args.run_directory.resolve()
            if directory.parent != WORK or not re.fullmatch(r"[0-9]{8}T[0-9]{6}-[a-f0-9]{8}", directory.name):
                raise ValueError("Expected an existing run directory under target/security-lab")
            if args.operation == "report":
                return int(not render_report(directory))
            else:
                Campaign(directory).cleanup()
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"security-lab: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
