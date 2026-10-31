"""Prepare frozen inputs and run isolated, observable local WAF suites."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

from evidence import (USER_AGENT, judge_agentic, judge_availability, judge_ban_recovery,
                      judge_connect, judge_crs, judge_ffuf, judge_ffuf_behavior,
                      judge_gotestwaf, judge_h2, judge_h3, judge_backpressure,
                      judge_credential_stuffing, judge_exploit_canary, judge_global_auth,
                      judge_mutations, judge_scraping,
                      judge_load, judge_nuclei, judge_protocol,
                      judge_replay, judge_response_leaks, judge_restart, judge_slow, judge_sqlmap,
                      judge_websocket_lifecycle, judge_zap, judge_zap_workflow,
                      origin_response, read_jsonl, summarize,
                      validate_agentic, validate_cases, validate_ffuf_cases,
                      validate_mutations, validate_protocol, verify_origin)

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
WORK = ROOT / "target/security-lab"
PREPARED = WORK / "prepared"
COMMAND_JOURNAL = None

MANUAL_CONFIGS = {
    "rules-origin.yaml": {"fixture": "origin", "logs": ("origin", "kunato")},
    "rules-dvwa.yaml": {"fixture": "dvwa", "logs": ("db", "dvwa", "kunato")},
    "rules-cve.yaml": {"fixture": "cve", "logs": ("cve", "kunato")},
    "rules-ffuf.yaml": {"fixture": "dvwa", "logs": ("db", "dvwa", "kunato")},
    "rules-ban.yaml": {"fixture": "origin", "logs": ("origin", "kunato")},
    "rules-backpressure.yaml": {"fixture": "origin", "logs": ("origin", "kunato")},
    "rules-availability.yaml": {"fixture": "origin", "logs": ("origin", "kunato")},
    "rules-connect.yaml": {"fixture": "none", "logs": ("kunato",)},
}
MANUAL_PROTECTED_CONFIGS = {"rules-ffuf.yaml", "rules-ban.yaml",
                            "rules-backpressure.yaml", "rules-availability.yaml"}
MANUAL_TOOLS = {"python": "python", "sqlmap": "sqlmap",
                "nuclei": "nuclei", "ffuf": "python"}

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
  header_read: 15s
  body_read: 2s
  upstream_connect: 1s
  upstream_response: 1s
  shutdown_grace: 10s
  connection_idle: 60s
"""

CONNECT_TIMEOUTS = """timeouts:
  header_read: 5s
  body_read: 2s
  upstream_connect: 1s
  upstream_response: 5s
  shutdown_grace: 10s
  connection_idle: 60s
"""

AVAILABILITY_PROTECTION = """protection:
  enabled: true
  max_connections_per_ip: 8
  max_connections: 32
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

BAN_PROTECTION = """protection:
  enabled: true
  max_connections_per_ip: 64
  max_connections: 256
  requests_per_second: 1
  burst: 1
  global_requests_per_second: 10000
  max_tracked_ips: 100
  aggregate_ipv6_prefix: 64
  ban:
    violations: 2
    window: 10s
    duration: 2s
    max_duration: 2s
  behavior:
    enabled: false
"""

SCRAPING_PROTECTION = """protection:
  enabled: true
  allowlist: [127.0.0.1/32]
  max_connections_per_ip: 64
  max_connections: 256
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
    enabled: true
    window: 60s
    min_requests: 1
    enumeration:
      enabled: false
    auth:
      enabled: false
    global_auth:
      enabled: false
    scraping:
      enabled: true
      action: BLOCK
      min_requests: 8
      distinct_paths: 8
"""

GLOBAL_AUTH_PROTECTION = """protection:
  enabled: true
  allowlist: [127.0.0.1/32]
  max_connections_per_ip: 64
  max_connections: 256
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
    enabled: true
    window: 60s
    min_requests: 1
    enumeration:
      enabled: false
    auth:
      enabled: false
    global_auth:
      enabled: true
      window: 60s
      min_failures: 6
      action: BLOCK
      ban: 10s
"""

BACKPRESSURE_PROTECTION = """protection:
  enabled: true
  max_connections_per_ip: 64
  max_connections: 256
  requests_per_second: 20
  burst: 20
  global_requests_per_second: 20
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


def parse_manual_publish(value):
    host, separator, port = value.rpartition(":")
    if not separator:
        host, port = "127.0.0.1", value
    if host in ("", "localhost"):
        host = "127.0.0.1"
    if host != "127.0.0.1":
        raise ValueError("--publish must bind the manual Kunato listener to 127.0.0.1")
    try:
        port = int(port)
    except ValueError as error:
        raise ValueError("--publish must be [127.0.0.1:]PORT") from error
    if not 1 <= port <= 65535:
        raise ValueError("--publish port must be between 1 and 65535")
    return host, port


def manual_listen_port(config_path):
    match = re.search(r"(?m)^listen:\s*0\.0\.0\.0:(\d+)\s*$", Path(config_path).read_text())
    if not match:
        raise ValueError(f"Cannot find the Kunato listener in {config_path}")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise ValueError(f"Kunato listener port is out of range in {config_path}")
    return port


class ManualForwarder(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, server_address, handler, *, limit=32):
        self.limit = threading.BoundedSemaphore(limit)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address):
        if not self.limit.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.limit.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.limit.release()


class ManualForwarderHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = socket.create_connection(self.server.target, timeout=5)
        try:
            self.request.settimeout(None)
            upstream.settimeout(None)
            threads = [threading.Thread(target=self._pipe,
                                        args=(self.request, upstream)),
                       threading.Thread(target=self._pipe,
                                        args=(upstream, self.request))]
            for thread in threads:
                thread.daemon = True
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            upstream.close()

    @staticmethod
    def _pipe(source, sink):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass


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
    for path in sorted([ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "examples/h3probe.rs",
                            *ROOT.glob("src/**/*.rs")]):
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
                            stdin=subprocess.DEVNULL,
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


def interactive_command(args):
    print("+ " + " ".join(str(arg) for arg in args), flush=True)
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT, check=False)
    if COMMAND_JOURNAL:
        with COMMAND_JOURNAL.open("a") as journal:
            journal.write(json.dumps({"argv": [str(arg) for arg in args],
                                      "exit_code": result.returncode}) + "\n")
    return result


def manual_terminate(signum, frame):
    raise KeyboardInterrupt


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
    command(["cargo", "build", "--release", "--locked", "--example", "h3probe"], timeout=900)
    if source_hash() != source_before:
        raise ValueError("Rust sources changed during the build; repeat prepare")
    shutil.copy2(ROOT / "target/release/kunato", PREPARED / "kunato")
    shutil.copy2(ROOT / "target/release/examples/h3probe", PREPARED / "h3probe")
    manifest = {"schema_version": 1, "platform": lock["platform"], "images": images,
                "fixtures": fixtures, "tools": tools, "tool_versions": lock["tool_versions"],
                "binary_sha256": sha256(PREPARED / "kunato"),
                "h3probe_sha256": sha256(PREPARED / "h3probe"),
                "source_sha256": source_hash(),
                "lock_sha256": sha256(LAB / "artifacts.lock.json")}
    write_json(PREPARED / "manifest.json", manifest)
    print(f"Prepared inputs: {PREPARED}")


def prepared_inputs():
    manifest = json.loads((PREPARED / "manifest.json").read_text())
    lock = json.loads((LAB / "artifacts.lock.json").read_text())
    if manifest["lock_sha256"] != sha256(LAB / "artifacts.lock.json"):
        raise ValueError("Image lock changed; run prepare")
    if (manifest["source_sha256"] != source_hash()
            or manifest["binary_sha256"] != sha256(PREPARED / "kunato")
            or manifest.get("h3probe_sha256") != sha256(PREPARED / "h3probe")):
        raise ValueError("Kunato sources or probes changed; run prepare")
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


# Placements are limited to the request parts each rule class inspects: SQL
# injection matches query, body, and cookies; XSS matches query, body, and
# headers; traversal matches query and body. Encoders are limited to forms whose
# decoded value is still the attack: percent encoding is decoded by form and
# JSON applications and by the cookie matcher, and JSON \u escapes are decoded
# by the body inspector. Base64, XML entities, and JSUnicode outside JSON change
# the value the origin receives, so asserting a block for them would report a
# false detection gap.
GOTESTWAF_SWEEPS = {
    "sql-injection": ("query", "form", "json", "cookie"),
    "xss": ("query", "form", "json", "header", "cookie"),
    "path-traversal": ("query", "form", "json"),
}
GOTESTWAF_ENCODERS = {
    "query": ("Plain",),
    "form": ("Plain", "URL"),
    "json": ("Plain", "JSUnicode"),
    "header": ("Plain",),
    "cookie": ("Plain", "URL"),
}
GOTESTWAF_PAYLOAD_HEADER = "X-Kunato-Lab-Payload"
GOTESTWAF_COOKIE_PREFIX = "session=lab-session"
_GO_PATH_SAFE = "$&+:=@-._~"


def go_path_escape(value):
    """Escape one path segment the way Go's url.PathEscape does."""
    return quote(value, safe=_GO_PATH_SAFE)


def go_js_unicode(value):
    """Encode UTF-16BE code units the way goTestWAF's JSUnicode encoder does."""
    encoded = value.encode("utf-16-be")
    return "".join(f"\\u{encoded[index]:02x}{encoded[index + 1]:02x}"
                   for index in range(0, len(encoded), 2))


def gotestwaf_payload(case):
    """Return the parameter name and attack value a smoke case carries."""
    if "body" in case:
        name, separator, value = case["body"].partition("=")
        if separator and name and all(character.isalnum() or character in "_-" for character in name):
            return name, value
        return "q", case["body"]
    pairs = parse_qsl(urlsplit(case["target"]).query, keep_blank_values=True)
    if len(pairs) != 1:
        raise ValueError("Sweep cases must carry exactly one query parameter")
    return pairs[0]


def gotestwaf_variant(case, name, payload, placement, encoder):
    case_id = f"{case['id']}--{placement}-{encoder.lower()}"
    request = {"method": "POST" if placement in {"form", "json"} else "GET",
               "path": f"/case/{case_id}", "headers": {}, "body": ""}
    if placement == "query":
        request["path"] += "?" + name + "={{payload}}"
    elif placement == "form":
        request["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        request["body"] = name + "={{payload}}"
    elif placement == "json":
        request["headers"] = {"Content-Type": "application/json"}
        request["body"] = '{"%s":"{{payload}}"}' % name
    elif placement == "header":
        request["headers"] = {GOTESTWAF_PAYLOAD_HEADER: "{{payload}}"}
    elif placement == "cookie":
        request["headers"] = {"Cookie": GOTESTWAF_COOKIE_PREFIX + "; " + name + "={{payload}}"}
    else:
        raise ValueError(f"Unknown goTestWAF placement: {placement}")
    return {"id": case_id, "expect": case["expect"], "placement": placement,
            "encoder": encoder, "name": name, "payload": payload, **request}


def gotestwaf_variants(cases):
    """Expand sweep cases into one goTestWAF case per encoder and placement."""
    variants = []
    for case in cases:
        sweep = case.get("sweep")
        if sweep is None:
            continue
        if sweep not in GOTESTWAF_SWEEPS:
            raise ValueError(f"Unknown goTestWAF sweep class: {sweep}")
        name, payload = gotestwaf_payload(case)
        if not payload:
            raise ValueError("Sweep cases must carry a payload")
        for placement in GOTESTWAF_SWEEPS[sweep]:
            for encoder in GOTESTWAF_ENCODERS[placement]:
                variants.append(gotestwaf_variant(case, name, payload, placement, encoder))
    if not variants:
        raise ValueError("Sweep cases produced no goTestWAF variants")
    return variants


def gotestwaf_wire(variant):
    """Return the exact target, body, payload header, and cookie the tool sends."""
    payload = variant["payload"]
    encoded = {"Plain": payload, "URL": go_path_escape(payload),
               "JSUnicode": go_js_unicode(payload)}[variant["encoder"]]
    if variant["placement"] == "query":
        return f"/case/{variant['id']}?{variant['name']}={go_path_escape(payload)}", "", "", ""
    return (variant["path"], variant["body"].replace("{{payload}}", encoded),
            encoded if variant["placement"] == "header" else "",
            variant["headers"].get("Cookie", "").replace("{{payload}}", encoded))


def verify_gotestwaf_wire(variants, origin):
    """Require every expected request to reach the origin unchanged."""
    receipts = {}
    for event in origin:
        if event.get("event") == "completed":
            receipts.setdefault(urlsplit(event.get("target", "")).path, []).append(event)
    for variant in variants:
        events = receipts.get(f"/case/{variant['id']}", [])
        if len(events) != 1:
            raise ValueError(f"Expected one origin receipt for {variant['id']}")
        event = events[0]
        target, body, payload_header, cookie = gotestwaf_wire(variant)
        if event.get("method") != variant["method"]:
            raise ValueError(f"goTestWAF changed the method for {variant['id']}")
        if event.get("target") != target:
            raise ValueError(f"goTestWAF changed the target for {variant['id']}")
        if event.get("body_sha256") != hashlib.sha256(body.encode()).hexdigest():
            raise ValueError(f"goTestWAF changed the body for {variant['id']}")
        if event.get("payload_header") != payload_header:
            raise ValueError(f"goTestWAF changed the payload header for {variant['id']}")
        if event.get("cookie") != cookie:
            raise ValueError(f"goTestWAF changed the cookie for {variant['id']}")
        if event.get("user_agent") != USER_AGENT:
            raise ValueError(f"goTestWAF changed the user agent for {variant['id']}")


def write_gotestwaf_cases(destination, cases):
    """Write one goTestWAF case per encoder and placement variant."""
    # JSON is a YAML subset accepted by goTestWAF; no Python YAML dependency.
    for variant in gotestwaf_variants(cases):
        directory = destination / ("attacks" if variant["expect"] == "block" else "false-pos")
        directory.mkdir(parents=True, exist_ok=True)
        request = {key: variant[key] for key in ("method", "path", "headers", "body")}
        data = {"payload": [variant["payload"]], "encoder": [variant["encoder"]],
                "type": "Kunato sweep", "placeholder": [{"RawRequest": request}]}
        write_json(directory / (variant["id"] + ".yml"), data)


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

    def front_network(self):
        return f"{self.project}_front"

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

    def manual_preflight(self):
        rendered = json.loads(self.compose("config", "--format", "json").stdout)
        for network in rendered["networks"].values():
            if not network.get("internal"):
                raise ValueError("Lab network has external connectivity")
            actual = command(["docker", "network", "inspect", network["name"]], check=False)
            if actual.returncode == 0 and not json.loads(actual.stdout)[0]["Internal"]:
                raise ValueError("Live Docker network is not internal")
        for service_config in rendered["services"].values():
            if (service_config.get("ports") or service_config.get("privileged")
                    or service_config.get("network_mode")):
                raise ValueError("Lab services cannot publish ports or use privileged/host networking")
        write_json(self.run_dir / "manual-compose.json", rendered)

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

    def surface(self, name, config="rules-origin.yaml"):
        cases_path = self.input / f"lab/cases/{name}.json"
        cases = json.loads(cases_path.read_text())
        validate_cases(cases)
        control_nonce = self.reset_origin(f"{name}-control", config=config)
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", f"/lab/cases/{name}.json"),
                              log=self.run_dir / f"{name}-control/probes.jsonl")
        control_origin, _ = self.logs(f"{name}-control")
        verify_origin(control_origin, control_nonce)
        for case, observation in zip(cases, controls, strict=True):
            observation["validated"] = origin_response(case, observation, control_nonce)
        if not all(observation["validated"] for observation in controls):
            raise ValueError(f"Direct {name} controls failed")
        write_json(self.run_dir / f"{name}-control/validated.json", controls)
        nonce = self.reset_origin(name, config=config)
        results = self.probe("client", "cases",
                             extra=("--cases", f"/lab/cases/{name}.json"),
                             log=self.run_dir / f"{name}/probes.jsonl")
        self.healthy(name, nonce=nonce)
        origin, waf = self.logs(name)
        return summarize(judge_replay(cases, controls, results, origin, waf, nonce))

    def jwt_policy(self):
        return self.surface("jwt", config="rules-jwt.yaml")

    def graphql(self):
        return self.surface("graphql", config="rules-graphql.yaml")

    def hardening(self):
        return self.surface("hardening", config="rules-hardening.yaml")

    def response_leaks(self):
        cases = json.loads((self.input / "lab/cases/response-leaks.json").read_text())
        validate_cases(cases)
        control_nonce = self.reset_origin("response-control")
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/cases/response-leaks.json"),
                              log=self.run_dir / "response-control/probes.jsonl")
        control_origin, _ = self.logs("response-control")
        verify_origin(control_origin, control_nonce)
        write_json(self.run_dir / "response-control/validated.json", controls)
        nonce = self.reset_origin("response")
        results = self.probe("client", "cases",
                             extra=("--cases", "/lab/cases/response-leaks.json"),
                             log=self.run_dir / "response/probes.jsonl")
        self.healthy("response", nonce=nonce)
        origin, waf = self.logs("response")
        return summarize(judge_response_leaks(cases, controls, results, origin, waf, nonce))

    def reset_vuln(self, phase):
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_CONFIG"] = "rules-vuln.yaml"
        self.env["LAB_DISABLE_PROTECTION"] = "1"
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "vuln", "kunato")
        directory = self.run_dir / phase
        directory.mkdir(exist_ok=True)
        for _ in range(50):
            health = self.probe("control", "health", check=False,
                                extra=("--host", "vuln", "--path", "/health",
                                       "--status", "200", "--nonce", nonce))
            if health.get("status") == 200 and health.get("origin") == nonce:
                write_json(directory / "health-before.json", health)
                write_json(directory / "attempt.json", {"nonce": nonce})
                return nonce
            time.sleep(0.2)
        raise RuntimeError("Vulnerable fixture did not become ready")

    def ssrf_xxe(self):
        cases = json.loads((self.input / "lab/cases/ssrf-xxe.json").read_text())
        validate_cases(cases)
        self.reset_vuln("ssrf-xxe-control")
        self.preflight("vuln")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/cases/ssrf-xxe.json",
                                     "--host", "vuln"),
                              log=self.run_dir / "ssrf-xxe-control/probes.jsonl")
        nonce = self.reset_vuln("ssrf-xxe")
        results = self.probe("client", "cases",
                             extra=("--cases", "/lab/cases/ssrf-xxe.json"),
                             log=self.run_dir / "ssrf-xxe/probes.jsonl")
        self.healthy("ssrf-xxe", nonce=nonce)
        directory = self.run_dir / "ssrf-xxe"
        self.compose("logs", "--no-color", "--no-log-prefix", "vuln",
                     log=directory / "vuln.log")
        self.compose("logs", "--no-color", "--no-log-prefix", "kunato",
                     log=directory / "kunato.jsonl")
        waf = read_jsonl(directory / "kunato.jsonl")
        return summarize(judge_exploit_canary(cases, controls, results, waf))

    def global_auth(self):
        cases = json.loads((self.input / "lab/cases/global-auth.json").read_text())
        validate_cases(cases)
        control_nonce = self.reset_origin("global-auth-control",
                                          config="rules-global-auth.yaml")
        self.preflight("origin")
        control_results = self.probe("control", "cases",
                                      extra=("--cases", "/lab/cases/global-auth.json"),
                                      log=self.run_dir / "global-auth-control/probes.jsonl")
        control = control_results[0]
        control_origin, _ = self.logs("global-auth-control")
        verify_origin(control_origin, control_nonce)
        if not origin_response(cases[0], control, control_nonce):
            raise ValueError("Global-auth direct control failed")
        write_json(self.run_dir / "global-auth-control/validated.json", control)

        nonce = self.reset_origin("global-auth", config="rules-global-auth.yaml",
                                  disable_protection=False)
        failures = []
        for service in ("client", "client-b"):
            for _ in range(3):
                failures.append(self.probe(
                    service, "cases",
                    extra=("--cases", "/lab/cases/global-auth.json"),
                    log=self.run_dir / f"global-auth/failure-{len(failures)}.jsonl")[0])
        blocked = self.probe("client", "cases",
                             extra=("--cases", "/lab/cases/global-auth.json"),
                             log=self.run_dir / "global-auth/blocked.jsonl")[0]
        self.healthy("global-auth", nonce=nonce)
        origin, waf = self.logs("global-auth")
        return judge_global_auth(control, failures, blocked, waf)

    def scraping(self):
        cases = json.loads((self.input / "lab/cases/scraping.json").read_text())
        validate_cases(cases)
        control_nonce = self.reset_origin("scraping-control",
                                          config="rules-scraping.yaml")
        self.preflight("origin")
        controls = self.probe("control", "cases",
                              extra=("--cases", "/lab/cases/scraping.json"),
                              log=self.run_dir / "scraping-control/probes.jsonl")
        control_origin, _ = self.logs("scraping-control")
        verify_origin(control_origin, control_nonce)
        nonce = self.reset_origin("scraping", config="rules-scraping.yaml",
                                  disable_protection=False)
        self.compose("up", "-d", "normal")
        results = self.probe("client", "cases",
                             extra=("--cases", "/lab/cases/scraping.json"),
                             log=self.run_dir / "scraping/probes.jsonl")
        self.healthy("scraping", service="normal", exec=True, nonce=nonce)
        origin, waf = self.logs("scraping")
        return judge_scraping(controls, results, waf)

    def credential_stuffing(self):
        cases = json.loads((self.input / "lab/cases/credential-stuffing.json").read_text())
        if len(cases) != 12 or any(not case.get("username") or not case.get("password")
                                   for case in cases):
            raise ValueError("Credential-stuffing cases must contain 12 username/password attempts")
        control_nonce = self.reset_origin("credential-stuffing-control")
        self.preflight("origin")
        controls = self.probe("control", "auth-spray",
                              extra=("--cases", "/lab/cases/credential-stuffing.json"),
                              log=self.run_dir / "credential-stuffing-control/probes.jsonl")
        control_origin, _ = self.logs("credential-stuffing-control")
        verify_origin(control_origin, control_nonce)
        nonce = self.reset_origin("credential-stuffing", disable_protection=False)
        results = self.probe("client", "auth-spray",
                             extra=("--cases", "/lab/cases/credential-stuffing.json"),
                             log=self.run_dir / "credential-stuffing/probes.jsonl")
        self.healthy("credential-stuffing", nonce=nonce)
        origin, waf = self.logs("credential-stuffing")
        return judge_credential_stuffing(controls, results, waf, expected=len(cases))

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

    def agentic(self):
        cases = json.loads((self.input / "lab/cases/agentic.json").read_text())
        validate_agentic(cases)
        control_dvwa_dir = self.run_dir / "agentic-dvwa-control"
        control_nonce = self.reset_dvwa("agentic-dvwa-control")
        self.seed_dvwa_canary(control_nonce)
        self.preflight("dvwa", ("db",))
        control_dvwa = self.probe("control", "agentic",
                                  extra=("--fixture", "dvwa", "--host", "dvwa",
                                         "--port", "80", "--canary", control_nonce),
                                  log=control_dvwa_dir / "probes.jsonl")
        write_json(control_dvwa_dir / "agentic.json", control_dvwa)
        nonce = self.reset_dvwa("agentic-dvwa")
        self.seed_dvwa_canary(nonce)
        self.preflight("dvwa", ("db",))
        self.compose("up", "-d", "normal")
        protected_dvwa = self.probe("client", "agentic",
                                    extra=("--fixture", "dvwa", "--canary", nonce),
                                    log=self.run_dir / "agentic-dvwa/probes.jsonl")
        write_json(self.run_dir / "agentic-dvwa/agentic.json", protected_dvwa)
        self.healthy("agentic-dvwa", path="/index.php", service="normal", exec=True)
        self.raw_logs("agentic-dvwa", "dvwa")
        _, waf_dvwa = self.logs("agentic-dvwa")

        control_cve_dir = self.run_dir / "agentic-cve-control"
        control_cve_nonce = self.reset_cve("agentic-cve-control")
        self.preflight("cve")
        control_cve = self.probe("control", "agentic",
                                 extra=("--fixture", "cve", "--host", "cve",
                                        "--port", "80", "--canary", control_cve_nonce),
                                 log=control_cve_dir / "probes.jsonl")
        write_json(control_cve_dir / "agentic.json", control_cve)
        cve_nonce = self.reset_cve("agentic-cve")
        self.preflight("cve")
        self.compose("up", "-d", "normal")
        protected_cve = self.probe("client", "agentic",
                                   extra=("--fixture", "cve", "--canary", cve_nonce),
                                   log=self.run_dir / "agentic-cve/probes.jsonl")
        write_json(self.run_dir / "agentic-cve/agentic.json", protected_cve)
        self.healthy("agentic-cve", path="/", service="normal", exec=True)
        self.raw_logs("agentic-cve", "cve")
        _, waf_cve = self.logs("agentic-cve")
        return judge_agentic(cases, control_dvwa, protected_dvwa,
                             control_cve, protected_cve, waf_dvwa, waf_cve)

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
        self.wait_active_connections(0, above=False)
        self.compose("--profile", "tools", "up", "-d", "--scale", "exhaust=4", "exhaust")
        active = self.wait_active_connections(32)
        time.sleep(2)
        global_cap = self.probe("client", "health", check=False,
                                extra=("--path", "/health", "--status", "503"))
        global_cap["active_connections"] = active
        self.compose("stop", "exhaust")
        self.compose("rm", "-f", "exhaust")
        self.wait_active_connections(0, above=False)
        upstream = self.probe("client", "upstream", check=False)
        normal = self.healthy("availability", nonce=nonce)
        after = self.stats()
        metrics_path = self.run_dir / "availability/metrics.json"
        application_metrics = (json.loads(metrics_path.read_text())
                               if metrics_path.exists() else {"response": ""})
        self.logs("availability")
        return judge_availability(slow, slow_body, slow_read, exhaustion, upstream,
                                  normal, before, after, self.restarts(),
                                  application_metrics, global_cap=global_cap)

    def active_connections(self):
        result = self.probe_exec("kunato", "metrics")
        for line in result.get("response", "").splitlines():
            if line.startswith("kunato_active_connections "):
                try:
                    return int(float(line.split(None, 1)[1]))
                except ValueError:
                    return None
        return None

    def wait_active_connections(self, target, above=True):
        for _ in range(100):
            active = self.active_connections()
            if active is not None and (active >= target if above else active <= target):
                return active
            time.sleep(0.1)
        raise RuntimeError(f"Kunato active connections did not reach {target}")

    def connect(self):
        self.env["LAB_CONFIG"] = "rules-connect.yaml"
        self.env["LAB_DISABLE_PROTECTION"] = "1"
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "kunato")
        self.wait_tcp()
        before = self.stats()
        result = self.probe("client", "upstream", check=False)
        after = self.stats()
        metrics = self.probe_exec("kunato", "metrics")
        self.logs("connect")
        return judge_connect(result, before, after, self.restarts(), metrics)

    def wait_tcp(self):
        for _ in range(50):
            result = self.probe("client", "connect", check=False)
            if result.get("connected"):
                return
            time.sleep(0.2)
        raise RuntimeError("Kunato did not start listening")

    def h2(self):
        self.reset_h2()
        self.preflight("origin")
        self.compose("up", "-d", "normal")
        before = self.stats()
        normal = self.probe("client", "h2", check=False,
                            extra=("--h2-case", "normal", "--case-id", "h2-normal",
                                   "--port", "8443"))
        rapid = self.probe("client", "h2", check=False,
                           extra=("--h2-case", "rapid-reset", "--port", "8443"))
        time.sleep(0.5)
        continuation = self.probe("client", "h2", check=False,
                                  extra=("--h2-case", "continuation", "--port", "8443"))
        time.sleep(0.5)
        hpack = self.probe("client", "h2", check=False,
                           extra=("--h2-case", "hpack", "--port", "8443"))
        time.sleep(0.5)
        made = self.probe("client", "h2", check=False,
                          extra=("--h2-case", "made-you-reset", "--port", "8443"))
        independent = self.probe_exec(
            "normal", "h2",
            extra=("--h2-case", "normal", "--case-id", "h2-independent",
                   "--port", "8443"))
        after = self.stats()
        origin, _ = self.logs("h2")
        metrics = self.probe_exec("kunato", "metrics")
        return judge_h2(normal, rapid, continuation, hpack, independent, origin,
                        before, after, self.restarts(), metrics,
                        made_you_reset=made)

    def reset_h2(self):
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_CONFIG"] = "rules-h2.yaml"
        self.env["LAB_DISABLE_PROTECTION"] = "1"
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "origin", "kunato")
        directory = self.run_dir / "h2"
        directory.mkdir(exist_ok=True)
        for _ in range(50):
            health = self.probe(
                "client", "h2", check=False,
                extra=("--h2-case", "normal", "--case-id", "h2-health",
                       "--port", "8443"))
            if health.get("ok"):
                time.sleep(0.2)
                origin, _ = self.logs("h2")
                try:
                    verify_origin(origin, nonce)
                except ValueError:
                    time.sleep(0.2)
                    continue
                write_json(directory / "health-before.json", health)
                write_json(directory / "attempt.json", {"nonce": nonce})
                return nonce
            time.sleep(0.2)
        raise RuntimeError("Kunato/origin did not become ready over HTTP/2")

    def binary_probe(self, service, *args):
        result = self.compose("run", "--rm", "--no-deps", "-T", service, *args,
                              check=False)
        return self.last_json(result)

    def exec_binary(self, service, *args):
        result = self.compose("exec", "-T", service, *args, check=False)
        return self.last_json(result)

    @staticmethod
    def last_json(result):
        for line in reversed(result.stdout.splitlines()):
            try:
                return json.loads(line)
            except ValueError:
                continue
        return {"probe_error": result.stderr[-1000:]
                or f"probe exited {result.returncode}"}

    @staticmethod
    def h3_args(case, case_id=None):
        args = ["--host", "app.test", "--port", "8443",
                "--cert", "/lab/fixtures/tls/ca.pem", "--case", case]
        if case_id:
            args += ["--case-id", case_id]
        return tuple(args)

    def h3(self):
        self.reset_h3()
        self.preflight("origin")
        self.compose("up", "-d", "normal")
        before = self.stats()
        normal = self.binary_probe("h3probe", *self.h3_args("normal", "h3-normal"))
        malformed = self.binary_probe("h3probe", *self.h3_args("malformed"))
        time.sleep(0.5)
        reset = self.binary_probe("h3probe", *self.h3_args("reset"))
        independent = self.binary_probe("h3probe", *self.h3_args("normal", "h3-independent"))
        after = self.stats()
        origin, _ = self.logs("h3")
        metrics = self.probe_exec("kunato", "metrics")
        return judge_h3(normal, malformed, reset, independent, origin,
                        before, after, self.restarts(), metrics)

    def reset_h3(self):
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_CONFIG"] = "rules-h3.yaml"
        self.env["LAB_DISABLE_PROTECTION"] = "1"
        self.compose("up", "-d", "--force-recreate", "--pull", "never", "origin", "kunato")
        directory = self.run_dir / "h3"
        directory.mkdir(exist_ok=True)
        last_health = {}
        for _ in range(50):
            health = self.binary_probe("h3probe", *self.h3_args("normal", "h3-health"))
            last_health = health
            write_json(directory / "probe.json", health)
            if health.get("ok"):
                time.sleep(0.2)
                origin, _ = self.logs("h3")
                try:
                    verify_origin(origin, nonce)
                except ValueError:
                    time.sleep(0.2)
                    continue
                write_json(directory / "health-before.json", health)
                write_json(directory / "attempt.json", {"nonce": nonce})
                return nonce
            time.sleep(0.2)
        raise RuntimeError(f"Kunato/origin did not become ready over HTTP/3: {last_health}")

    def backpressure(self):
        nonce = self.reset_origin("backpressure", config="rules-backpressure.yaml",
                                  disable_protection=False)
        self.preflight("origin")
        before = self.stats()
        burst = self.probe("client", "burst", check=False,
                           extra=("--requests", "100"))
        time.sleep(1.2)
        normal = self.healthy("backpressure", nonce=nonce)
        after = self.stats()
        metrics_path = self.run_dir / "backpressure/metrics.json"
        application_metrics = (json.loads(metrics_path.read_text())
                               if metrics_path.exists() else {"response": ""})
        self.logs("backpressure")
        return judge_backpressure(burst, normal, before, after, self.restarts(),
                                  application_metrics)

    def ban(self):
        nonce = self.reset_origin("ban", config="rules-ban.yaml",
                                  disable_protection=False)
        self.preflight("origin")
        self.compose("up", "-d", "normal")
        before = self.stats()
        probe = self.probe("client", "ban",
                           extra=("--requests", "10", "--hold", "3"), check=False)
        normal = self.healthy("ban", nonce=nonce, service="normal", exec=True)
        after = self.stats()
        metrics_path = self.run_dir / "ban/metrics.json"
        application_metrics = (json.loads(metrics_path.read_text())
                               if metrics_path.exists() else {"response": ""})
        self.logs("ban")
        return judge_ban_recovery(probe, normal, before, after, self.restarts(),
                                  application_metrics)

    def websocket(self):
        self.reset_origin("websocket-control")
        self.preflight("origin")
        control = self.probe("control", "ws-lifecycle", check=False,
                             log=self.run_dir / "websocket-control/probes.jsonl")
        control_payload = self.probe(
            "control", "ws-payload", check=False,
            log=self.run_dir / "websocket-control/payload.jsonl")
        control_push = self.probe(
            "control", "ws-push", check=False,
            log=self.run_dir / "websocket-control/push.jsonl")
        nonce = self.reset_origin("websocket")
        self.compose("up", "-d", "normal")
        protected = self.probe("client", "ws-lifecycle", check=False,
                               log=self.run_dir / "websocket/probes.jsonl")
        protected_payload = self.probe(
            "client", "ws-payload", check=False,
            log=self.run_dir / "websocket/payload.jsonl")
        protected_push = self.probe(
            "client", "ws-push", check=False,
            log=self.run_dir / "websocket/push.jsonl")
        normal = self.healthy("websocket", nonce=nonce, service="normal", exec=True)
        self.logs("websocket")
        return judge_websocket_lifecycle(control, protected, normal,
                                         control_payload, protected_payload,
                                         control_push, protected_push)

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
        cases = json.loads((self.input / "lab/cases/smoke.json").read_text())
        variants = gotestwaf_variants(cases)
        planned = {variant["id"]: variant["expect"] for variant in variants}
        nonce, origin, _, report = self.tool_attempt("gotestwaf-control", "gotestwaf-control")
        controls = judge_gotestwaf(report, origin, [], nonce, planned, control=True)
        if not all(case["verdict"] == "passed" for case in controls):
            raise ValueError("goTestWAF direct receipt controls failed")
        verify_gotestwaf_wire(variants, origin)
        nonce, origin, waf, report = self.tool_attempt("gotestwaf", "gotestwaf")
        verify_gotestwaf_wire([variant for variant in variants if variant["expect"] == "allow"],
                              origin)
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

    def seed_dvwa_canary(self, nonce):
        value = f"CANARY-{nonce}"
        self.compose("exec", "-T", "-u", "0", "dvwa", "sh", "-c",
                     f"printf '%s' '{value}' > /tmp/kunato-lab-agentic-canary "
                     "&& chmod 0644 /tmp/kunato-lab-agentic-canary")
        check = self.compose("exec", "-T", "dvwa", "cat",
                             "/tmp/kunato-lab-agentic-canary")
        if check.stdout.strip() != value:
            raise ValueError("DVWA file canary was not seeded")
        return value

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

    def reset_cve(self, phase, *, disable_protection=True):
        self.compose("rm", "-s", "-f", "-v", "db", "dvwa", check=False)
        self.compose("rm", "-s", "-f", "cve", check=False)
        nonce = uuid.uuid4().hex
        self.env["LAB_NONCE"] = nonce
        self.env["LAB_DISABLE_PROTECTION"] = "1" if disable_protection else "0"
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

    def manual_up(self, config, *, disable_protection, dvwa_auth=False):
        fixture = MANUAL_CONFIGS[config]["fixture"]
        if fixture == "dvwa":
            return self.reset_dvwa("manual", config=config,
                                   disable_protection=disable_protection,
                                   auth_disabled=not dvwa_auth)
        if fixture == "cve":
            return self.reset_cve("manual", disable_protection=disable_protection)
        if fixture == "origin":
            return self.reset_origin("manual", config=config,
                                     disable_protection=disable_protection)
        if config == "rules-connect.yaml":
            self.env["LAB_CONFIG"] = config
            self.env["LAB_DISABLE_PROTECTION"] = "1" if disable_protection else "0"
            self.compose("up", "-d", "--force-recreate", "--pull", "never", "kunato")
            self.wait_tcp()
            return None
        raise ValueError(f"Unsupported manual configuration: {config}")

    def container_ip(self, service, network):
        container_id = self.compose("ps", "-q", service).stdout.strip()
        if not container_id:
            raise ValueError(f"Manual fixture {service} is not running")
        container = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
        for name, settings in container["NetworkSettings"]["Networks"].items():
            if name == network and settings.get("IPAddress"):
                return settings["IPAddress"]
        raise ValueError(f"Manual fixture {service} has no address on {network}")

    def manual_forwarder(self, host_port, container_port):
        server = ManualForwarder(("127.0.0.1", host_port), ManualForwarderHandler)
        server.target = (self.container_ip("kunato", self.front_network()), container_port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def manual_shell_command(self, tool, *, target_port=8080, canary=None):
        args = ["docker", "run", "--rm", "-i"]
        if sys.stdin.isatty() and sys.stdout.isatty():
            args.append("-t")
        args += ["--name", f"{self.project}-shell",
                 "--network", self.front_network(),
                 "--user", "65532:65532", "--read-only",
                 "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges:true",
                 "--init",
                 "--pids-limit", "64", "--memory", "256m",
                 "--memory-swap", "256m", "--cpus", "1",
                 "--tmpfs", "/tmp:size=67108864,mode=1777",
                 "-e", "HOME=/tmp",
                 "-e", f"LAB_TARGET=http://app.test:{target_port}",
                 "-w", "/tmp",
                 "-v", f"{self.input / 'lab'}:/lab:ro"]
        if canary:
            args += ["-e", f"LAB_CANARY={canary}"]
        if tool == "ffuf":
            args += ["-v", f"{self.input / 'ffuf'}:/usr/local/bin/ffuf:ro"]
        args += ["--entrypoint", "sh",
                 self.manifest["images"][MANUAL_TOOLS[tool]]["id"]]
        return args

    def manual_evidence(self, config):
        directory = self.run_dir / "manual"
        directory.mkdir(parents=True, exist_ok=True)
        for service in MANUAL_CONFIGS[config]["logs"]:
            self.compose("logs", "--no-color", "--no-log-prefix", service,
                         check=False, log=directory / f"{service}.log")
        self.compose("ps", "--all", "--format", "json", check=False,
                     log=directory / "containers.json")
        metrics = self.compose("exec", "-T", "kunato", "python3", "-B",
                               "/lab/probe.py", "metrics", check=False)
        if metrics.returncode == 0:
            (directory / "metrics.json").write_text(metrics.stdout)
        return directory

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
                if exit_status.returncode == 0 and exit_status.stdout.strip():
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
        container = self.compose("ps", "-q", "kunato").stdout.strip()
        if not container:
            return 0
        result = command(["docker", "inspect", "--format", "{{.RestartCount}}", container],
                         check=False)
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

    def restart(self):
        nonce = self.reset_origin("restart")
        self.preflight("origin")
        self.compose("up", "-d", "normal")
        before = self.stats()
        self.start_tool("restart", "restart-load", [], "k6")
        container = self.compose("ps", "-q", "kunato").stdout.strip()
        if not container:
            raise ValueError("Kunato container is not running")
        try:
            time.sleep(5)
            started = time.monotonic()
            command(["docker", "kill", "--signal=TERM", container])
            while True:
                state = command(["docker", "inspect", "--format",
                                 "{{.State.Running}} {{.State.ExitCode}}", container],
                                check=False).stdout.strip()
                running, _, exit_code = state.partition(" ")
                if running == "false":
                    break
                if time.monotonic() - started > 20:
                    raise ValueError("Kunato did not exit after SIGTERM")
                time.sleep(0.1)
            shutdown_ms = round((time.monotonic() - started) * 1000, 2)
            exit_code = int(exit_code or "1")
            command(["docker", "start", container])
            recovery = self.wait_health("restart-recovery", "client",
                                        ("--path", "/health"), nonce=nonce)
        finally:
            self.finish_tool("restart", "restart-load", "k6", 120, "k6-summary.json")
        summary = json.loads((self.run_dir / "restart/k6-summary.json").read_text())
        after = self.stats()
        normal = self.healthy("restart", nonce=nonce, service="normal", exec=True)
        self.logs("restart")
        return judge_restart(summary, exit_code, shutdown_ms, recovery, normal,
                             before, after)

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
    shutil.copy2(PREPARED / "h3probe", input_dir / "h3probe")
    shutil.copy2(PREPARED / "ffuf", input_dir / "ffuf")
    config_dir = input_dir / "config"
    config_dir.mkdir()
    original = (ROOT / "rules.example.yaml").read_text()
    (config_dir / "rules.example.yaml").write_text(original)
    for name, upstream in (("rules-origin.yaml", "http://origin:8080"),
                           ("rules-dvwa.yaml", "http://dvwa:80"),
                           ("rules-cve.yaml", "http://cve:80"),
                           ("rules-vuln.yaml", "http://vuln:8080")):
        (config_dir / name).write_text(make_config(original, upstream))
    (config_dir / "rules-ffuf.yaml").write_text(
        make_config(original, "http://dvwa:80", FFUF_PROTECTION))
    (config_dir / "rules-availability.yaml").write_text(
        make_config(original, "http://origin:8080", AVAILABILITY_PROTECTION,
                    timeouts=AVAILABILITY_TIMEOUTS))
    (config_dir / "rules-connect.yaml").write_text(
        make_config(original, "http://172.30.250.250:8080",
                    timeouts=CONNECT_TIMEOUTS))
    h2, listeners = re.subn(r"(?m)^listen: .*", "listen: 0.0.0.0:8443",
                            make_config(original, "http://origin:8080"))
    if listeners != 1:
        raise ValueError("Expected one listener for the H2 configuration")
    h2 += ("\ntls:\n"
           "  cert_file: /lab/fixtures/tls/cert.pem\n"
           "  key_file: /lab/fixtures/tls/key.pem\n")
    (config_dir / "rules-h2.yaml").write_text(h2)
    (config_dir / "rules-h3.yaml").write_text(h2 + "http3: { enabled: true }\n")
    (config_dir / "rules-ban.yaml").write_text(
        make_config(original, "http://origin:8080", BAN_PROTECTION))
    (config_dir / "rules-backpressure.yaml").write_text(
        make_config(original, "http://origin:8080", BACKPRESSURE_PROTECTION))
    jwt_config = make_config(original, "http://origin:8080")
    jwt_config, count = re.subn(
        r"(?ms)^  jwt:\n(?:    [^\n]*\n)+",
        """  jwt:
    enabled: true
    allowed_algorithms: [RS256]
    require_exp: true
    allowed_issuers: [https://issuer.example]
    allowed_audiences: [kunato-lab]
    leeway: 30s
""",
        jwt_config,
    )
    if count != 1:
        raise ValueError("Expected one disabled jwt limits block")
    (config_dir / "rules-jwt.yaml").write_text(jwt_config)
    (config_dir / "rules-global-auth.yaml").write_text(
        make_config(original, "http://origin:8080", GLOBAL_AUTH_PROTECTION))
    (config_dir / "rules-scraping.yaml").write_text(
        make_config(original, "http://origin:8080", SCRAPING_PROTECTION))
    graphql_config = make_config(original, "http://origin:8080")
    graphql_config, count = re.subn(
        r"(?m)^    block_introspection: false$",
        "    block_introspection: true",
        graphql_config,
    )
    if count != 1:
        raise ValueError("Expected one disabled graphql introspection setting")
    (config_dir / "rules-graphql.yaml").write_text(graphql_config)
    hardening_config = make_config(original, "http://origin:8080")
    hardening_config, count = re.subn(
        r"(?ms)^  hardening:\n(?:    [^\n]*\n)+",
        """  hardening:
    ssrf:
      enabled: true
      internal_hosts: [vuln.corp]
      internal_suffixes: []
    duplicate_parameters:
      enabled: true
      json_keys: true
      allow_parameters: [tag]
    cache_deception:
      enabled: true
      static_suffixes: [.avif]
      auth_cookies: [session]
    redirects:
      enabled: true
      allowed_hosts: [app.test]
      parameters: [redirect_uri]
""",
        hardening_config,
    )
    if count != 1:
        raise ValueError("Expected one disabled hardening block")
    (config_dir / "rules-hardening.yaml").write_text(hardening_config)
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
    for name in ("common", "recent", "response-leaks", "graphql", "ssrf-xxe", "jwt",
                 "global-auth", "hardening", "scraping"):
        validate_cases(json.loads((LAB / f"cases/{name}.json").read_text()))
    validate_agentic(json.loads((LAB / "cases/agentic.json").read_text()))
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
                     "rules-vuln.yaml", "rules-jwt.yaml", "rules-global-auth.yaml",
                     "rules-hardening.yaml", "rules-graphql.yaml", "rules-scraping.yaml",
                     "rules-ffuf.yaml",
                     "rules-availability.yaml", "rules-connect.yaml",
                     "rules-h2.yaml", "rules-h3.yaml", "rules-ban.yaml",
                     "rules-backpressure.yaml"):
            lab.compose("run", "--rm", "--no-deps", "-T", "kunato",
                        "--config", f"/config/{name}", "--validate")
        report["suites"]["replay"] = lab.replay()
        if suite in {"benign", "all"}:
            report["suites"]["benign"] = lab.benign()
        if suite in {"mutations", "all"}:
            report["suites"]["mutations"] = lab.mutations()
        if suite in {"protocol", "all"}:
            report["suites"]["protocol"] = lab.protocol()
        if suite in {"common", "all"}:
            report["suites"]["common"] = lab.surface("common")
        if suite in {"recent", "all"}:
            report["suites"]["recent"] = lab.surface("recent")
        if suite in {"response", "all"}:
            report["suites"]["response"] = lab.response_leaks()
        if suite in {"graphql", "all"}:
            report["suites"]["graphql"] = lab.graphql()
        if suite in {"jwt", "all"}:
            report["suites"]["jwt"] = lab.jwt_policy()
        if suite in {"hardening", "all"}:
            report["suites"]["hardening"] = lab.hardening()
        if suite in {"ssrf-xxe", "all"}:
            report["suites"]["ssrf-xxe"] = lab.ssrf_xxe()
        if suite in {"credential-stuffing", "all"}:
            report["suites"]["credential-stuffing"] = lab.credential_stuffing()
        if suite in {"scraping", "all"}:
            report["suites"]["scraping"] = lab.scraping()
        if suite in {"global-auth", "all"}:
            report["suites"]["global-auth"] = lab.global_auth()
        if suite in {"agentic", "all"}:
            report["suites"]["agentic"] = lab.agentic()
        if suite in {"slow", "all"}:
            report["suites"]["slow"] = lab.slow()
        if suite in {"availability", "all"}:
            report["suites"]["availability"] = lab.availability()
        if suite in {"connect", "all"}:
            report["suites"]["connect"] = lab.connect()
        if suite in {"h2", "all"}:
            report["suites"]["h2"] = lab.h2()
        if suite in {"h3", "all"}:
            report["suites"]["h3"] = lab.h3()
        if suite in {"backpressure", "all"}:
            report["suites"]["backpressure"] = lab.backpressure()
        if suite in {"ban", "all"}:
            report["suites"]["ban"] = lab.ban()
        if suite in {"websocket", "all"}:
            report["suites"]["websocket"] = lab.websocket()
        if suite in {"load", "all"}:
            report["suites"]["load"] = lab.load()
        if suite in {"restart", "all"}:
            report["suites"]["restart"] = lab.restart()
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


def print_manual_banner(lab, config, *, disable_protection, tool, published,
                        container_port, nonce, interactive):
    fixture = MANUAL_CONFIGS[config]["fixture"]
    health_path = {"origin": "/health",
                   "dvwa": "/vulnerabilities/sqli/?id=1&Submit=Submit",
                   "cve": "/", "none": "/health"}[fixture]
    print("Manual lab ready", flush=True)
    print(f"  run:        {lab.run_dir}", flush=True)
    print(f"  config:     {config}", flush=True)
    print(f"  protection: {'disabled' if disable_protection else 'enabled'}", flush=True)
    print(f"  network:    {lab.front_network()}", flush=True)
    print(f"  target:     http://app.test:{container_port}", flush=True)
    if published:
        print(f"  published:  {published} (loopback only)", flush=True)
        print(f"  host:       curl -H 'Host: app.test' {published}{health_path}",
              flush=True)
    print(f"  evidence:   {lab.run_dir / 'manual'}", flush=True)
    if config == "rules-connect.yaml":
        print("  upstream:   blackhole; requests return 502 after the connect timeout",
              flush=True)
    if config == "rules-cve.yaml" and nonce:
        print(f"  canary:     kunato-lab-canary-{nonce}", flush=True)
    if tool == "python":
        print(f"  example:    python3 -c \"import urllib.request; "
              f"print(urllib.request.urlopen('$LAB_TARGET{health_path}')"
              f".read().decode())\"", flush=True)
    elif tool == "sqlmap":
        print(f"  example:    python3 /sqlmap/sqlmap.py -u "
              f"\"$LAB_TARGET{health_path}\" --batch", flush=True)
        if fixture != "dvwa":
            print("  note:       use --config rules-dvwa.yaml for the SQLi fixture",
                  flush=True)
    elif tool == "nuclei":
        print("  example:    nuclei -u \"$LAB_TARGET\" "
              "-t /lab/templates/cve-2021-41773-canary.yaml -duc -ni", flush=True)
        if config == "rules-cve.yaml" and nonce:
            print("              -var canary=\"$LAB_CANARY\" "
                  f"-var \"user_agent={USER_AGENT}\"", flush=True)
        elif fixture != "cve":
            print("  note:       use --config rules-cve.yaml for the canary fixture",
                  flush=True)
    elif tool == "ffuf":
        print("  example:    ffuf -u \"$LAB_TARGET/FUZZ\" "
              "-w /lab/plans/ffuf-paths.txt "
              f"-H \"User-Agent: {USER_AGENT}\" -mc all", flush=True)
    print("  stop:       exit the shell" if interactive else "  stop:       press Ctrl-C",
          flush=True)


def manual_shell(args):
    global COMMAND_JOURNAL
    config = args.config
    if config not in MANUAL_CONFIGS:
        raise ValueError(f"Unsupported manual configuration: {config}")
    if args.dvwa_auth and MANUAL_CONFIGS[config]["fixture"] != "dvwa":
        raise ValueError("--dvwa-auth requires rules-dvwa.yaml or rules-ffuf.yaml")
    disable_protection = (config not in MANUAL_PROTECTED_CONFIGS
                          if args.protection is None else not args.protection)
    publish = parse_manual_publish(args.publish) if args.publish else None
    directory = new_run("manual")
    COMMAND_JOURNAL = directory / "commands.jsonl"
    container_port = manual_listen_port(directory / "input" / "config" / config)
    published = None
    forwarder = None
    lab = SandboxSuite(directory)
    signal.signal(signal.SIGTERM, manual_terminate)
    status = 0
    try:
        nonce = lab.manual_up(config, disable_protection=disable_protection,
                              dvwa_auth=args.dvwa_auth)
        lab.manual_preflight()
        if publish:
            host, host_port = publish
            forwarder = lab.manual_forwarder(host_port, container_port)
            published = f"http://{host}:{host_port}"
        (directory / "manual").mkdir(exist_ok=True)
        write_json(directory / "manual" / "summary.json",
                   {"run_id": directory.name, "mode": "manual", "config": config,
                    "protection": not disable_protection, "tool": args.tool,
                    "published": published,
                    "target": f"http://app.test:{container_port}",
                    "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
        print_manual_banner(lab, config, disable_protection=disable_protection,
                            tool=args.tool, published=published,
                            container_port=container_port, nonce=nonce,
                            interactive=not args.no_shell)
        if args.no_shell:
            while True:
                time.sleep(3600)
        else:
            canary = (f"kunato-lab-canary-{nonce}"
                      if config == "rules-cve.yaml" and nonce else None)
            result = interactive_command(
                lab.manual_shell_command(args.tool, target_port=container_port,
                                         canary=canary))
            if result.returncode:
                print(f"security-lab: manual shell exited {result.returncode}",
                      file=sys.stderr)
                status = 1
    except KeyboardInterrupt:
        print("\nStopping the manual lab.", flush=True)
    finally:
        if forwarder is not None:
            try:
                forwarder.shutdown()
                forwarder.server_close()
            except OSError as error:
                print(f"security-lab: manual relay shutdown failed: {error}",
                      file=sys.stderr)
                status = 1
        command(["docker", "rm", "-f", f"{lab.project}-shell"], check=False, quiet=True)
        try:
            lab.manual_evidence(config)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"security-lab: manual evidence collection failed: {error}",
                  file=sys.stderr)
            status = 1
        try:
            lab.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"security-lab: cleanup failed: {error}", file=sys.stderr)
            status = 1
        print(f"Manual evidence: {directory}", flush=True)
    return status


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
                        choices=["replay", "benign", "mutations", "protocol", "common", "recent",
                                 "response", "graphql", "jwt", "hardening", "ssrf-xxe",
                                 "credential-stuffing", "global-auth", "scraping",
                                 "agentic", "gotestwaf", "sqlmap", "nuclei", "ffuf", "zap", "crs",
                                 "slow", "availability", "connect", "h2", "h3",
                                 "backpressure", "ban", "websocket", "load", "restart",
                                 "all"],
                        default="replay")
    shell = subs.add_parser("shell", aliases=["manual"],
                            help="Start a persistent manual lab and attack shell")
    shell.add_argument("--config", choices=sorted(MANUAL_CONFIGS),
                       default="rules-origin.yaml")
    shell.add_argument("--tool", choices=sorted(MANUAL_TOOLS), default="python")
    shell.add_argument("--publish", metavar="[127.0.0.1:]PORT",
                       help="Expose Kunato through a loopback relay for host tools")
    shell.add_argument("--no-shell", action="store_true",
                       help="Keep the lab running without opening a shell")
    shell.add_argument("--dvwa-auth", action="store_true",
                       help="Enable the seeded DVWA login")
    protection = shell.add_mutually_exclusive_group()
    protection.add_argument("--protection", dest="protection", action="store_true",
                            default=None, help="Force protection on")
    protection.add_argument("--no-protection", dest="protection", action="store_false",
                            help="Force protection off")
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
        elif args.operation in {"shell", "manual"}:
            return manual_shell(args)
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
