"""Lab-only receipt fixture for interactive attacker testing.

Every request is written to stdout as one JSON line before the response is
sent, so the origin log is the ground truth for "did the request pass the
WAF". Responses are canned: the fixture never executes code, reads files,
opens sockets, or persists state.
"""

import hashlib
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

MAX_BODY = 65536
MAX_EVENTS = 100000
MAX_HEADERS = 64
MAX_HEADER_VALUE = 1024
BREACH_CANARY = "kunato-lab-breach-canary"
NONCE = os.environ.get("LAB_NONCE", "")

SQL_META = ("'", '"', "--", "/*", " or 1=1", "union select", "sleep(")
XSS_META = ("<script", "onerror=", "onload=", "javascript:", "<svg")
TRAVERSAL_META = ("..", "%2e%2e", "%252e")
INTERNAL_META = ("127.0.0.1", "localhost", "169.254.", "file:", "gopher:",
                 "metadata.google.internal", "0.0.0.0")
EXECUTABLE_SUFFIXES = (".php", ".php5", ".phtml", ".jsp", ".jspx", ".war",
                       ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh")

PAGES = {
    "/": b"""<!DOCTYPE html>
<html><head><title>Inventory</title></head><body>
<h1>Inventory</h1>
<form action="/search" method="get"><input name="q" value="widget"><button>Search</button></form>
<form action="/login" method="post">
<input name="username" value="alice"><input name="password" type="password"><button>Sign in</button></form>
<ul>
<li><a href="/item?id=1">Item 1</a></li>
<li><a href="/fetch?url=https://example.com/">Fetch URL</a></li>
<li><a href="/download?file=readme.txt">Download</a></li>
<li><a href="/admin">Admin</a></li>
<li><a href="/api/graphql">GraphQL</a></li>
</ul>
</body></html>
""",
}


def printable(value, limit=512):
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    text = "".join(char if " " <= char <= "~" else " " for char in text)
    return text[:limit]


def digest(value):
    return hashlib.sha256(value).hexdigest() if value else ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "posture/1.0"
    events = 0

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def emit(self, event, **fields):
        if Handler.events > MAX_EVENTS:
            return
        Handler.events += 1
        record = {"event": event, "nonce": NONCE, "time": round(time.time(), 3)}
        record.update(fields)
        print(json.dumps(record), flush=True)

    def headers_record(self):
        record = {}
        for index, name in enumerate(self.headers, start=1):
            if index > MAX_HEADERS:
                break
            lowered = name.lower()
            record[lowered] = record.get(lowered, "") + self.headers.get_all(name)[0][:MAX_HEADER_VALUE]
        return record

    def body(self):
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding"):
            return None
        if length is None:
            return b""
        try:
            size = int(length)
        except ValueError:
            return None
        if size < 0 or size > MAX_BODY:
            return None
        data = self.rfile.read(size)
        return data if len(data) == size else None

    def query(self):
        return {key: values[0] for key, values in parse_qs(urlsplit(self.path).query).items()}

    def form(self, body):
        try:
            text = body.decode("utf-8", "replace")
        except AttributeError:
            return {}
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                value = json.loads(text)
            except ValueError:
                return {}
            return {str(key): str(item) for key, item in value.items()} if isinstance(value, dict) else {}
        return {key: values[0] for key, values in parse_qs(text).items()}

    def outcome(self, path, params, body):
        blob = (path + "?" + "&".join(f"{k}={v}" for k, v in params.items())).lower()
        text = printable(body, 4096).lower()
        if path == "/login" and any(marker in (params.get("username", "") + text).lower()
                                    for marker in SQL_META):
            return "sqli-login"
        if path == "/search" and any(marker in unquote(blob) for marker in XSS_META):
            return "reflected-xss"
        if path == "/download" and any(marker in unquote(blob) for marker in TRAVERSAL_META):
            return "path-traversal"
        if path == "/fetch" and any(marker in unquote(blob) for marker in INTERNAL_META):
            return "ssrf"
        if path == "/upload":
            name = params.get("filename", "") or text
            if any(suffix in name for suffix in EXECUTABLE_SUFFIXES) or "<?php" in text:
                return "upload-execution"
        if path == "/admin" and (params.get("role") == "admin"
                                 or self.headers.get("X-Admin") == "true"):
            return "authz-bypass"
        if path == "/item" and params.get("id", "1") != "1":
            return "idor"
        if path in {"/.env", "/.git/config", "/backup.zip", "/server-status"}:
            return "secret-exposure"
        return "none"

    def record(self, params, body, outcome):
        self.emit("received",
                  id=Handler.events,
                  method=self.command,
                  target=self.path[:8192],
                  version=self.request_version,
                  headers=self.headers_record(),
                  body_bytes=len(body or b""),
                  body_sha256=digest(body),
                  body_preview=printable(body),
                  outcome=outcome)

    def respond(self, status, body, content_type="application/json", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Kunato-Lab-Origin", NONCE)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.close_connection = True

    def answer(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        params = self.query()
        body = self.body()
        if body is None:
            self.emit("rejected", method=self.command, target=self.path[:8192],
                      reason="unsupported-body")
            self.respond(413, b'{"error":"unsupported body"}')
            return
        form = self.form(body)
        merged = {**params, **form}
        if path == "/upload":
            merged["filename"] = self.multipart_filename(body) or merged.get("filename", "")
        outcome = self.outcome(path, merged, body)
        self.record(merged, body, outcome)
        self.route(path, merged, outcome)

    @staticmethod
    def multipart_filename(body):
        for line in body.split(b"\r\n"):
            if b"filename=" in line.lower():
                text = line.decode("utf-8", "replace")
                name = text.split("filename=", 1)[1].strip().strip('"')
                return os.path.basename(name)[:200]
        return ""

    def route(self, path, params, outcome):
        if path == "/health":
            self.respond(200, json.dumps({"status": "ok", "origin": NONCE}))
        elif path == "/":
            self.respond(200, PAGES["/"], "text/html; charset=utf-8")
        elif path == "/search":
            query = printable(params.get("q", ""), 200)
            page = ("<!DOCTYPE html><html><body><h1>Results</h1>"
                    f"<p>No matches for {query}</p></body></html>")
            self.respond(200, page, "text/html; charset=utf-8")
        elif path == "/login":
            if outcome == "sqli-login":
                self.respond(200, json.dumps({"user": "admin", "role": "admin",
                                              "canary": BREACH_CANARY}),
                             headers={"Set-Cookie": "session=admin; Path=/"})
            else:
                self.respond(401, json.dumps({"error": "invalid credentials"}),
                             headers={"Set-Cookie": "session=guest; Path=/"})
        elif path == "/item":
            self.respond(200, json.dumps({"id": params.get("id", "1"), "owner": "alice",
                                          "secret": BREACH_CANARY if outcome == "idor" else ""}))
        elif path == "/fetch":
            target = printable(params.get("url", ""), 300)
            content = "remote content" if outcome != "ssrf" else BREACH_CANARY
            self.respond(200, json.dumps({"url": target, "content": content}))
        elif path == "/download":
            if outcome == "path-traversal":
                self.respond(200, BREACH_CANARY + "\n", "text/plain; charset=utf-8")
            else:
                self.respond(200, "readme\n", "text/plain; charset=utf-8")
        elif path == "/upload":
            stored = "/uploads/" + (params.get("filename") or "upload.bin")
            self.respond(200, json.dumps({"stored": stored,
                                          "executed": outcome == "upload-execution",
                                          "canary": BREACH_CANARY if outcome == "upload-execution" else ""}))
        elif path == "/api/graphql":
            self.respond(200, json.dumps({"data": {"__typename": "Query",
                                                   "viewer": {"id": 1, "role": "admin"}}}))
        elif path == "/admin":
            if outcome == "authz-bypass":
                self.respond(200, json.dumps({"panel": "admin", "canary": BREACH_CANARY}))
            else:
                self.respond(403, json.dumps({"error": "admin only"}))
        elif path == "/.env":
            self.respond(200, "APP_ENV=production\nDB_PASSWORD=lab-only-placeholder\n"
                              f"LAB_CANARY={BREACH_CANARY}\n", "text/plain; charset=utf-8")
        elif path == "/.git/config":
            self.respond(200, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                              "\turl = https://git.example.invalid/inventory.git\n",
                         "text/plain; charset=utf-8")
        elif path == "/redirect":
            self.respond(302, b"", headers={"Location": params.get("next", "/")})
        elif path == "/robots.txt":
            self.respond(200, "User-agent: *\nDisallow: /admin\n", "text/plain; charset=utf-8")
        else:
            self.respond(404, json.dumps({"error": "not found"}))

    def do_GET(self):
        self.answer()

    def do_POST(self):
        self.answer()

    def do_HEAD(self):
        self.answer()

    def do_OPTIONS(self):
        self.answer()

    def do_PUT(self):
        self.answer()

    def do_DELETE(self):
        self.answer()

    def do_PATCH(self):
        self.answer()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


def main():
    port = int(os.environ.get("LAB_PORT", "8080"))
    server = Server(("0.0.0.0", port), Handler)
    print(json.dumps({"event": "ready", "nonce": NONCE, "port": port}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
