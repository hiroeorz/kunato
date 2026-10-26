"""Lab-only SSRF and XXE fixture with an in-process callback sink."""

import json
import os
import re
import socketserver
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

NONCE = os.environ["LAB_NONCE"]
CANARY = "/tmp/kunato-lab-canary.txt"
SINK = ("127.0.0.1", 9000)


class SinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = f"sink:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class AppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Kunato-Lab-Origin", NONCE)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            self.reply(200, json.dumps({"status": "ok", "nonce": NONCE}).encode())
            return
        if path == "/safe":
            self.reply(200, b"safe")
            return
        if path == "/fetch":
            target = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
            if not target:
                self.reply(400, b"missing url")
                return
            try:
                with urllib.request.urlopen(target, timeout=3) as response:
                    body = response.read(4096)
                self.reply(200, body)
            except (OSError, ValueError, urllib.error.URLError) as error:
                self.reply(502, f"fetch failed: {error}".encode()[:512])
            return
        self.reply(404, b"not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path != "/xml":
            self.reply(404, b"not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(min(length, 65536)).decode("utf-8", errors="replace")
        match = re.search(r'SYSTEM\s+"file://([^"]+)"', body)
        if match:
            try:
                with open(match.group(1), "rb") as entity:
                    content = entity.read(4096)
            except OSError as error:
                self.reply(500, f"entity failed: {error}".encode()[:512])
                return
            self.reply(200, content)
            return
        match = re.search(r'SYSTEM\s+"(https?://[^"]+)"', body)
        if match:
            try:
                with urllib.request.urlopen(match.group(1), timeout=3) as response:
                    content = response.read(4096)
            except (OSError, ValueError, urllib.error.URLError) as error:
                self.reply(502, f"entity failed: {error}".encode()[:512])
                return
            self.reply(200, content)
            return
        self.reply(200, b"xml-ok")


class Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    with open(CANARY, "w", encoding="utf-8") as canary:
        canary.write(f"CANARY-{NONCE}\n")
    sink = Sink(SINK, SinkHandler)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), AppHandler)
    print(json.dumps({"event": "ready", "nonce": NONCE}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
