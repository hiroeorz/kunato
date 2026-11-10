"""Bounded loopback decoy replay against a local Kunato binary, without scanners or an LLM."""

import argparse
import collections
import hashlib
import http.client
import http.server
import json
import re
import signal
import subprocess
import tempfile
import threading
from pathlib import Path

HOST = "decoy.example.test"
TOKEN = re.compile(r"kdt1\.[0-9a-f]{16}\.[0-9a-f]{16}\.[0-9a-f]{32}\.[0-9a-f]{32}\.[0-9a-f]{64}")


def request(address, path, source="203.0.113.7", method="GET", headers=None):
    connection = http.client.HTTPConnection(*address, timeout=3)
    try:
        connection.request(method, path, headers={"Host": HOST,
                           "X-Forwarded-For": source, "Connection": "close",
                           **(headers or {})})
        response = connection.getresponse()
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("probe response exceeds limit")
        return response.status, body.decode("utf-8"), dict(response.getheaders())
    finally:
        connection.close()


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.receipts.append(self.headers.get("X-Kunato-Lab-Case"))
        body = b"healthy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def configuration(upstream, enabled, action):
    return f"""listen: 127.0.0.1:0
upstream: http://127.0.0.1:{upstream}
admin: {{listen: 127.0.0.1:0}}
client_ip: {{trusted_proxies: [127.0.0.1]}}
protection:
  requests_per_second: 1000
  burst: 1000
  behavior:
    sequence: {{action: BLOCK, threshold: 1, min_dimensions: 1, min_windows: 1}}
admin_access: {{enabled: true, default: close}}
decoys:
  enabled: {str(enabled).lower()}
  on_reuse: {action}
  sites:
    - name: loopback
      origin: https://{HOST}
      sink: /_decoy/api
      presets: [dotenv]
categories:
  - name: replay-block
    action: BLOCK
    rules:
      - name: blocked-route
        match: {{path: '^/blocked/'}}
"""


def collect_logs(pipe, events, addresses, ready, admin_ready):
    while line := pipe.readline(8193):
        if len(line) > 8192:
            events.append({"error": "log line exceeded probe bound"})
            return
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            events.append({"error": "invalid JSON log"})
            continue
        events.append(event)
        fields = event.get("fields", {})
        if fields.get("message") in {"kunato started", "admin listening"}:
            name = "main" if fields["message"] == "kunato started" else "admin"
            host, port = fields["addr"].rsplit(":", 1)
            if host != "127.0.0.1":
                events.append({"error": "listener escaped loopback"})
                return
            addresses[name] = (host, int(port))
            (ready if name == "main" else admin_ready).set()


def run_mode(binary, directory, action, cases):
    enabled = action != "OFF"
    origin = http.server.HTTPServer(("127.0.0.1", 0), Origin)
    origin.receipts = []
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    path = directory / f"{action.lower()}.yaml"
    path.write_text(configuration(origin.server_port, enabled, "LOG" if not enabled else action))
    events = collections.deque(maxlen=256)
    addresses, ready, admin_ready = {}, threading.Event(), threading.Event()
    process = subprocess.Popen([str(binary), "--config", str(path), "--log-format", "json",
                                "--log-level", "debug"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    reader = threading.Thread(target=collect_logs, args=(process.stdout, events, addresses,
                                                        ready, admin_ready), daemon=True)
    reader.start()
    results = []
    try:
        if not ready.wait(5) or not admin_ready.wait(5):
            raise AssertionError(f"Kunato did not start: {list(events)[-4:]}")
        status, body, headers = request(addresses["main"], "/.env",
                                        headers={"X-Kunato-Lab-Case": "issued"})
        assert status == 200, status
        match = TOKEN.search(body)
        if not enabled:
            assert match is None and origin.receipts == ["issued"]
            results.append({"id": "disabled-control", "status": status, "origin": True})
        else:
            assert match and not origin.receipts
            assert headers.get("cache-control") == "no-store"
            token = match.group()
            token_id = hashlib.sha256(token.encode()).hexdigest()[:32]
            once = "".join(f"%{ord(char):02x}" for char in token)
            twice = once.replace("%", "%25")
            replacements = {"{{TOKEN}}": token, "{{ONCE}}": once, "{{TWICE}}": twice}

            def substitute(value):
                for name, replacement in replacements.items():
                    value = value.replace(name, replacement)
                return value

            for index, case in enumerate(cases, 1):
                status, _, _ = request(addresses["main"], substitute(case["path"]),
                                       source=f"198.51.100.{index}", method=case["method"],
                                       headers={"X-Kunato-Lab-Case": case["id"],
                                                **{name: substitute(value) for name, value
                                                   in case.get("headers", {}).items()}})
                expected = case.get("status", case.get(f"{action.lower()}_status"))
                assert status == expected, (case["id"], status, expected)
                received = case["id"] in origin.receipts
                assert received == case["origin"], (case["id"], "origin receipt", received)
                results.append({"id": case["id"], "status": status, "origin": received})
            status, metrics, _ = request(addresses["admin"], "/metrics", headers={"Host": "localhost"})
            assert status == 200
            expected_blocked = int(action == "BLOCK")
            assert f"kunato_decoy_blocked_total {expected_blocked}\n" in metrics
            assert 'kunato_decoy_reuse_total{context="credential"} 1\n' in metrics
            fields = [event.get("fields", {}) for event in list(events)]
            issued = [field for field in fields if field.get("message") == "decoy credential issued"]
            reused = [field for field in fields if field.get("message") == "decoy credential returned"]
            assert any(field.get("token_id") == token_id and field.get("client") == "203.0.113.7" for field in issued)
            assert any(field.get("token_id") == token_id and field.get("client") == "198.51.100.1"
                       and field.get("context") == "credential" for field in reused)
            serialized = json.dumps(list(events))
            for sensitive in (token, once, twice):
                assert sensitive not in serialized, "token leaked into logs"
            assert any(field.get("path") == "[redacted]" for field in fields)
        return {"action": action, "passed": True, "cases": results,
                "origin_receipts": list(origin.receipts), "logs": list(events)}
    except Exception as error:
        return {"action": action, "passed": False, "cases": results, "error": str(error),
                "origin_receipts": list(origin.receipts), "logs": list(events)}
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        reader.join(timeout=2)
        process.stdout.close()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=2)


def run(binary, output):
    cases_path = Path(__file__).with_name("cases") / "decoys.json"
    cases = json.loads(cases_path.read_text())
    assert len(cases) <= 32 and len({case["id"] for case in cases}) == len(cases)
    report = {"passed": False, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(), "modes": []}
    try:
        with tempfile.TemporaryDirectory(prefix="kunato-decoy-probe-") as directory:
            for action in ("OFF", "LOG", "BLOCK"):
                mode = run_mode(binary, Path(directory), action, cases)
                report["modes"].append(mode)
                if not mode["passed"]:
                    raise AssertionError(f"{action} replay failed: {mode['error']}")
        report["passed"] = True
    finally:
        output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.binary.resolve(strict=True), args.output)
    print(json.dumps({"passed": report["passed"], "modes": len(report["modes"]),
                      "cases": sum(len(mode["cases"]) for mode in report["modes"]),
                      "report": str(args.output)}))


if __name__ == "__main__":
    main()
