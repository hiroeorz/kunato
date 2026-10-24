"""Bounded recording origin; no vulnerability or exploit-success claims."""

import hashlib
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY = 65536
MAX_EVENTS = 10000


class Recorder(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    events = 0

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_args):
        pass

    def emit(self, event, **fields):
        Recorder.events += 1
        print(json.dumps({"event": event, "nonce": os.environ["LAB_NONCE"], **fields}), flush=True)

    def do_GET(self):
        self.record()

    def do_POST(self):
        self.record()

    def record(self):
        self.close_connection = True
        if Recorder.events >= MAX_EVENTS:
            self.send_error(503, "Recorder event budget exhausted")
            return
        case_id = self.headers.get("X-Kunato-Lab-Case", "")
        debug_id = self.headers.get("X-GoTestWAF-Test", "")
        self.emit("received", case_id=case_id, debug_id=debug_id,
                  method=self.command, target=self.path[:8192],
                  user_agent=self.headers.get("User-Agent", "")[:512])
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("Unsupported or oversized body")
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError("Incomplete body")
        except (ValueError, OSError, socket.timeout) as error:
            self.emit("error", case_id=case_id, debug_id=debug_id, error=str(error))
            self.send_error(400)
            return
        status = {"/status/302": 302, "/status/401": 401, "/status/404": 404}.get(self.path, 200)
        result = {"origin": os.environ["LAB_NONCE"], "case_id": case_id,
                  "method": self.command, "target": self.path,
                  "user_agent": self.headers.get("User-Agent", ""),
                  "body_sha256": hashlib.sha256(body).hexdigest()}
        payload = json.dumps(result).encode()
        self.emit("completed", **result, debug_id=debug_id, status=status, body_bytes=len(body))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        if status == 302:
            self.send_header("Location", "/status/200")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    print(json.dumps({"event": "ready", "nonce": os.environ["LAB_NONCE"]}), flush=True)
    HTTPServer(("0.0.0.0", 8080), Recorder).serve_forever()
