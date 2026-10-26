"""Bounded recording origin; no vulnerability or exploit-success claims."""

import base64
import hashlib
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 65536
MAX_EVENTS = 10000
LARGE_BODY = 8 << 20
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class Recorder(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    events = 0

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_args):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def emit(self, event, **fields):
        Recorder.events += 1
        print(json.dumps({"event": event, "nonce": os.environ["LAB_NONCE"], **fields}), flush=True)

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.websocket()
            return
        if self.path.startswith("/leak/"):
            self.leak()
            return
        if self.path == "/slow-upstream":
            time.sleep(float(os.environ.get("LAB_SLOW_UPSTREAM", "3")))
        self.record()

    def do_POST(self):
        self.record()

    def do_PRI(self):
        self.record()

    def read_chunked(self):
        body = b""
        while True:
            line = self.rfile.readline(128)
            if not line or len(line) > 127:
                raise ValueError("Invalid chunk line")
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as error:
                raise ValueError("Invalid chunk size") from error
            if size < 0 or size > MAX_BODY:
                raise ValueError("Oversized chunk")
            if size == 0:
                while True:
                    trailer = self.rfile.readline(1024)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                return body
            data = self.rfile.read(size)
            if len(data) != size:
                raise ValueError("Incomplete chunk")
            body += data
            if len(body) > MAX_BODY:
                raise ValueError("Oversized body")
            if self.rfile.read(2) != b"\r\n":
                raise ValueError("Invalid chunk terminator")

    def read_body(self):
        transfer = self.headers.get("Transfer-Encoding")
        length = self.headers.get("Content-Length")
        framing = "cl"
        if transfer and length:
            framing = os.environ.get("LAB_ORIGIN_FRAMING", "reject")
            if framing not in {"cl", "te"}:
                raise ValueError("Ambiguous request framing")
        elif transfer:
            if transfer.strip().lower() != "chunked":
                raise ValueError("Unsupported transfer encoding")
            framing = "te"
        if framing == "te":
            return self.read_chunked()
        if length is None:
            return b""
        size = int(length)
        if not 0 <= size <= MAX_BODY:
            raise ValueError("Unsupported or oversized body")
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError("Incomplete body")
        return body

    def websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key or self.headers.get("Sec-WebSocket-Version") != "13":
            self.send_error(400, "Invalid WebSocket handshake")
            return
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        if self.path.startswith("/ws-push"):
            pushed = (b"-----BEGIN RSA PRIVATE KEY-----"
                      if self.path == "/ws-push-attack" else b"benign push")
            self.wfile.write(bytes([0x81, len(pushed)]) + pushed)
            self.wfile.flush()
        fragmented = bytearray()
        fragment_opcode = None
        try:
            while True:
                header = self.rfile.read(2)
                if len(header) != 2:
                    return
                first, second = header
                fin = bool(first & 0x80)
                opcode = first & 0x0F
                masked = second & 0x80
                length = second & 0x7F
                if length == 126:
                    length = int.from_bytes(self.rfile.read(2), "big")
                elif length == 127:
                    length = int.from_bytes(self.rfile.read(8), "big")
                if length > MAX_BODY or not masked:
                    return
                mask = self.rfile.read(4)
                payload = bytes(byte ^ mask[index % 4]
                                for index, byte in enumerate(self.rfile.read(length)))
                if opcode == 0x8:
                    self.wfile.write(bytes([0x88, len(payload)]) + payload)
                    self.wfile.flush()
                    return
                if opcode == 0x9:
                    self.wfile.write(bytes([0x8A, len(payload)]) + payload)
                    self.wfile.flush()
                    continue
                if opcode == 0xA:
                    continue
                if opcode in (0x1, 0x2):
                    if fragment_opcode is not None:
                        return
                    if not fin:
                        fragmented = bytearray(payload)
                        fragment_opcode = opcode
                        continue
                    response = b"echo:" + payload
                    response_opcode = opcode
                elif opcode == 0x0:
                    if fragment_opcode is None:
                        return
                    fragmented.extend(payload)
                    if not fin:
                        continue
                    response = b"echo:" + bytes(fragmented)
                    response_opcode = fragment_opcode
                    fragment_opcode = None
                else:
                    return
                self.emit("websocket", case_id=self.headers.get("X-Kunato-Lab-Case", ""),
                          method="GET", target=self.path[:8192],
                          frame_bytes=len(response) - 5)
                if len(response) > 125:
                    return
                self.wfile.write(bytes([0x80 | response_opcode, len(response)]) + response)
                self.wfile.flush()
        except (OSError, socket.timeout, ValueError):
            return

    def leak(self):
        case_id = self.headers.get("X-Kunato-Lab-Case", "")
        path = self.path.split("?", 1)[0]
        self.emit("received", case_id=case_id, method=self.command,
                  target=self.path[:8192], user_agent=self.headers.get("User-Agent", "")[:512])
        status, body, headers = {
            "/leak/private-key": (
                200,
                b"-----BEGIN RSA PRIVATE KEY-----\n"
                b"lab-only placeholder key material\n"
                b"-----END RSA PRIVATE KEY-----\n",
                {}),
            "/leak/sql-error": (
                500,
                b"You have an error in your SQL syntax; check the manual that "
                b"corresponds to your MySQL server version near 'union select' at line 1",
                {}),
            "/leak/django-debug": (
                500,
                b"You're seeing this error because you have DEBUG = True in your "
                b"Django settings file. Change that to False, and Django will "
                b"display a standard 500 page.",
                {}),
            "/leak/stack-trace": (
                500,
                b"Traceback (most recent call last):\n"
                b"  File \"app.py\", line 42, in view\n"
                b"RuntimeError: lab stack trace",
                {}),
            "/leak/server-version": (
                200, b"ok", {"Server": "nginx/1.18.0"}),
            "/leak/session-cookie": (
                200, b"ok", {"Set-Cookie": "PHPSESSID=" + "a" * 420}),
            "/leak/benign-404": (404, b'{"error":"not found"}', {}),
            "/leak/benign-500": (500, b'{"error":"internal"}', {}),
        }.get(path, (404, b'{"error":"unknown leak fixture"}', {}))
        self.emit("completed", case_id=case_id, method=self.command,
                  target=self.path[:8192], status=status, body_bytes=len(body),
                  user_agent=self.headers.get("User-Agent", "")[:512])
        if "Server" in headers:
            self.server_version = headers.pop("Server")
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def record(self):
        if Recorder.events >= MAX_EVENTS:
            self.send_error(503, "Recorder event budget exhausted")
            return
        case_id = self.headers.get("X-Kunato-Lab-Case", "")
        debug_id = self.headers.get("X-GoTestWAF-Test", "")
        self.emit("received", case_id=case_id, debug_id=debug_id,
                  method=self.command, target=self.path[:8192],
                  user_agent=self.headers.get("User-Agent", "")[:512])
        try:
            body = self.read_body()
        except (ValueError, OSError, socket.timeout) as error:
            self.emit("error", case_id=case_id, debug_id=debug_id, error=str(error))
            self.send_error(400)
            return
        status = {"/status/302": 302, "/status/401": 401, "/status/404": 404}.get(self.path, 200)
        if self.path == "/login" and self.command == "POST":
            status = 401
        if self.path == "/api/private" and (
                "session=lab-session" not in self.headers.get("Cookie", "")
                or self.headers.get("Authorization", "") != "Bearer lab-token"):
            status = 401
        result = {"origin": os.environ["LAB_NONCE"], "case_id": case_id,
                  "method": self.command, "target": self.path,
                  "user_agent": self.headers.get("User-Agent", ""),
                  "body_sha256": hashlib.sha256(body).hexdigest()}
        payload = json.dumps(result).encode()
        self.emit("completed", **result, debug_id=debug_id, status=status, body_bytes=len(body))
        if self.path == "/stream":
            self.send_chunked(payload)
            return
        if self.path == "/stream-slow":
            self.send_chunked_slow(payload)
            return
        if self.path == "/large":
            self.send_large()
            return
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "keep-alive" if not self.close_connection else "close")
            if status == 302:
                self.send_header("Location", "/status/200")
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_chunked(self, payload):
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            for start in range(0, len(payload), 2048):
                part = payload[start:start + 2048]
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_chunked_slow(self, payload):
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            for start in range(0, len(payload), 64):
                part = payload[start:start + 64]
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_large(self):
        self.close_connection = True
        chunk = b"x" * 8192
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Kunato-Lab-Origin", os.environ["LAB_NONCE"])
            self.send_header("Content-Length", str(LARGE_BODY))
            self.send_header("Connection", "close")
            self.end_headers()
            for _ in range(LARGE_BODY // len(chunk)):
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    print(json.dumps({"event": "ready", "nonce": os.environ["LAB_NONCE"]}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Recorder).serve_forever()
