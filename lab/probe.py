"""One-shot HTTP probes in a front-only or short-lived control container."""

import argparse
import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from pathlib import Path

from evidence import USER_AGENT


def request(case, host="app.test", port=8080):
    connection = http.client.HTTPConnection(host, port, timeout=4)
    headers = {"User-Agent": USER_AGENT, "X-Kunato-Lab-Case": case["id"],
               "Connection": "close", **case.get("headers", {})}
    body = case.get("body", "").encode()
    result = {"id": case["id"], "method": case["method"], "target": case["target"],
              "body_sha256": hashlib.sha256(body).hexdigest()}
    started = time.monotonic()
    try:
        connection.request(case["method"], case["target"], body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(65537)
        if len(content) > 65536:
            raise ValueError("Response exceeds probe limit")
        result.update(status=response.status, origin=response.getheader("X-Kunato-Lab-Origin"),
                      response=content.decode("utf-8", errors="replace"))
    except (OSError, ValueError, http.client.HTTPException) as error:
        result["error"] = str(error)
    finally:
        connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def raw_request(case, host="app.test", port=8080):
    started = time.monotonic()
    result = {"id": case["id"], "method": case.get("method", "RAW"),
              "target": case.get("target", ""), "bytes": 0, "status": None,
              "responses": []}
    raw = case.get("raw", "")
    if "raw_repeat" in case:
        raw = (case.get("raw_prefix", "") + "a" * int(case["raw_repeat"])
               + case.get("raw_suffix", ""))
    try:
        connection = socket.create_connection((host, port), timeout=4)
        connection.sendall(raw.encode("latin-1"))
        connection.settimeout(float(case.get("read_timeout", 1.0)))
        data = b""
        if "ws_frame" in case:
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                data += chunk
            connection.sendall(case["ws_frame"].encode("latin-1"))
        while len(data) < 262144:
            try:
                chunk = connection.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        connection.close()
        text = data.decode("latin-1")
        statuses = [int(match) for match in re.findall(r"HTTP/1\.[01] (\d{3})", text)]
        result.update(bytes=len(data), response=text, responses=statuses,
                      status=statuses[0] if statuses else None)
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def slow_request(case, host="app.test", port=8080):
    started = time.monotonic()
    count = int(case.get("connections", 8))
    hold = float(case.get("hold_seconds", 2))
    sockets = []
    sent = 0
    responses = []
    try:
        for _ in range(count):
            connection = socket.create_connection((host, port), timeout=4)
            connection.sendall(b"GET /slow HTTP/1.1\r\nHost: app.test\r\n")
            connection.settimeout(0.5)
            sockets.append(connection)
            sent += 1
        time.sleep(hold)
        for connection in sockets:
            try:
                responses.append(len(connection.recv(4096)))
            except socket.timeout:
                responses.append(0)
            finally:
                connection.close()
    except OSError as error:
        return {"id": "slow", "error": str(error), "sent": sent,
                "responses": responses, "held_seconds": hold,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}
    return {"id": "slow", "sent": sent, "responses": responses,
            "closed": sum(1 for size in responses if size), "held_seconds": hold,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}


def status_of(data):
    text = data.decode("latin-1")
    statuses = [int(match) for match in re.findall(r"HTTP/1\.[01] (\d{3})", text)]
    return (statuses[0] if statuses else None), text


def slow_body(case, host="app.test", port=8080):
    started = time.monotonic()
    hold = float(case.get("hold_seconds", 3))
    length = int(case.get("length", 16))
    connection = None
    result = {"id": "slow-body", "sent": 0, "held_seconds": hold, "status": None}
    try:
        connection = socket.create_connection((host, port), timeout=4)
        head = (f"POST /slow-body HTTP/1.1\r\nHost: app.test\r\n"
                f"Content-Length: {length}\r\nX-Kunato-Lab-Case: slow-body\r\n\r\n")
        connection.sendall(head.encode("latin-1"))
        connection.sendall(b"x")
        result["sent"] = 1
        time.sleep(hold)
        connection.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        status, text = status_of(data)
        result.update(status=status, response=text[:4096])
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def slow_read(case, host="app.test", port=8080):
    started = time.monotonic()
    hold = float(case.get("hold_seconds", 2))
    connection = None
    result = {"id": "slow-read", "status": None, "held_seconds": hold}
    try:
        connection = socket.create_connection((host, port), timeout=4)
        connection.sendall(b"GET /large HTTP/1.1\r\nHost: app.test\r\n"
                           b"X-Kunato-Lab-Case: slow-read\r\n\r\n")
        connection.settimeout(4)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        status, _ = status_of(data)
        result.update(status=status, headers_bytes=len(data))
        time.sleep(hold)
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def hold_connections(case, host="app.test", port=8080):
    started = time.monotonic()
    count = int(case.get("connections", 8))
    hold = float(case.get("hold_seconds", 20))
    sockets = []
    result = {"id": "hold", "opened": 0, "held_seconds": hold}
    try:
        for _ in range(count):
            connection = socket.create_connection((host, port), timeout=4)
            connection.sendall(b"GET /slow HTTP/1.1\r\nHost: app.test\r\n")
            sockets.append(connection)
            result["opened"] += 1
        time.sleep(hold)
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        for connection in sockets:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def exhaustion(case, host="app.test", port=8080):
    started = time.monotonic()
    count = int(case.get("connections", 8))
    sockets = []
    result = {"id": "exhaustion", "opened": 0, "status": None}
    try:
        for _ in range(count):
            connection = socket.create_connection((host, port), timeout=4)
            connection.sendall(b"GET /slow HTTP/1.1\r\nHost: app.test\r\n")
            connection.settimeout(0.5)
            sockets.append(connection)
            result["opened"] += 1
        time.sleep(0.3)
        probe = socket.create_connection((host, port), timeout=4)
        probe.sendall(b"GET /health HTTP/1.1\r\nHost: app.test\r\n"
                      b"X-Kunato-Lab-Case: exhaustion\r\n\r\n")
        probe.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = probe.recv(4096)
            if not chunk:
                break
            data += chunk
        status, text = status_of(data)
        result.update(status=status, response=text[:4096])
        probe.close()
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        for connection in sockets:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def connect(host="app.test", port=8080):
    try:
        connection = socket.create_connection((host, port), timeout=2)
    except OSError as error:
        return {"id": "connect", "connected": False, "error": str(error)}
    connection.close()
    return {"id": "connect", "connected": True}


def slow_upstream(host="app.test", port=8080):
    started = time.monotonic()
    connection = None
    result = {"id": "slow-upstream", "status": None}
    try:
        connection = socket.create_connection((host, port), timeout=4)
        connection.sendall(b"GET /slow-upstream HTTP/1.1\r\nHost: app.test\r\n"
                           b"X-Kunato-Lab-Case: slow-upstream\r\n\r\n")
        connection.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        status, text = status_of(data)
        result.update(status=status, response=text[:4096])
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def ban_recovery(case, host="app.test", port=8080):
    started = time.monotonic()
    count = int(case.get("requests", 8))
    hold = float(case.get("hold_seconds", 3))
    result = {"id": "ban", "statuses": [], "recovery_status": None,
              "held_seconds": hold}
    for _ in range(count):
        observation = request({"id": "ban-probe", "method": "GET",
                               "target": "/health"}, host, port)
        result["statuses"].append(observation.get("status") or observation.get("error"))
    result["banned"] = any(status == 429 for status in result["statuses"])
    time.sleep(hold)
    recovery = request({"id": "ban-recovery", "method": "GET",
                        "target": "/health"}, host, port)
    result["recovery_status"] = recovery.get("status")
    result["recovery_error"] = recovery.get("error")
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def ws_frame(opcode, payload, fin=True):
    mask = b"\x01\x02\x03\x04"
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])
    elif length < 65536:
        header = bytes([first, 0x80 | 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, 0x80 | 127]) + length.to_bytes(8, "big")
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + masked


def recv_exact(connection, length):
    data = b""
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ValueError("WebSocket peer closed early")
        data += chunk
    return data


class WSReader:
    """Reads frames while preserving bytes that arrive with the handshake."""

    def __init__(self, connection, buffer=b""):
        self.connection = connection
        self.buffer = buffer

    def read_exact(self, length):
        while len(self.buffer) < length:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise ValueError("WebSocket peer closed early")
            self.buffer += chunk
        data = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return data

    def read_frame(self):
        first, second = self.read_exact(2)
        length = second & 0x7F
        if length == 126:
            length = int.from_bytes(self.read_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self.read_exact(8), "big")
        mask = self.read_exact(4) if second & 0x80 else b""
        payload = self.read_exact(length)
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return first & 0x0F, bool(first & 0x80), payload


def ws_handshake(connection, path, case):
    key = base64.b64encode(f"kunato-lab-{case}".encode()).decode()
    request = (f"GET {path} HTTP/1.1\r\nHost: app.test\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               f"X-Kunato-Lab-Case: {case}\r\n\r\n")
    connection.sendall(request.encode("latin-1"))
    connection.settimeout(4)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    status, _ = status_of(data)
    end = data.find(b"\r\n\r\n")
    return status, (data[end + 4:] if end >= 0 else b"")


def websocket_lifecycle(host="app.test", port=8080):
    started = time.monotonic()
    connection = None
    result = {"id": "ws-lifecycle", "status": None, "pong": False,
              "echo": None, "closed": False}
    try:
        connection = socket.create_connection((host, port), timeout=4)
        status, leftover = ws_handshake(connection, "/ws-lifecycle", "ws-lifecycle")
        result["status"] = status
        if status != 101:
            return result
        reader = WSReader(connection, leftover)
        connection.sendall(ws_frame(0x9, b"ping"))
        opcode, _, payload = reader.read_frame()
        result["pong"] = opcode == 0xA and payload == b"ping"
        connection.sendall(ws_frame(0x1, b"frag", fin=False))
        connection.sendall(ws_frame(0x0, b"ment", fin=False))
        connection.sendall(ws_frame(0x0, b"ed", fin=True))
        opcode, _, payload = reader.read_frame()
        if opcode == 0x1:
            result["echo"] = payload.decode("utf-8", errors="replace")
        connection.sendall(ws_frame(0x8, b"\x03\xe8"))
        try:
            opcode, _, _ = reader.read_frame()
            result["closed"] = opcode == 0x8
        except (OSError, ValueError):
            result["closed"] = True
    except (OSError, ValueError) as error:
        result["error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def ws_open(host, port, case, path="/ws-lifecycle"):
    connection = socket.create_connection((host, port), timeout=4)
    status, leftover = ws_handshake(connection, path, case)
    return connection, status, leftover


def ws_payload(host="app.test", port=8080):
    started = time.monotonic()
    result = {"id": "ws-payload", "status": None, "blocked": False,
              "close_code": None, "echo": None, "benign_echo": None}
    for phase, payload in (("attack", b"<script>alert(1)</script>"),
                           ("benign", b"benign payload")):
        connection = None
        try:
            connection, status, leftover = ws_open(host, port, f"ws-payload-{phase}")
            result["status"] = result["status"] or status
            if status != 101:
                continue
            reader = WSReader(connection, leftover)
            connection.sendall(ws_frame(0x1, payload))
            opcode, _, data = reader.read_frame()
            if opcode == 0x8:
                if phase == "attack":
                    result["blocked"] = True
                    result["close_code"] = int.from_bytes(data[:2], "big")
            elif opcode == 0x1:
                text = data.decode("utf-8", errors="replace")
                if phase == "attack":
                    result["echo"] = text
                else:
                    result["benign_echo"] = text
        except (OSError, ValueError) as error:
            result["error"] = str(error)
        finally:
            if connection is not None:
                connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def ws_push(host="app.test", port=8080):
    started = time.monotonic()
    result = {"id": "ws-push", "status": None, "blocked": False,
              "close_code": None, "payload": None, "benign": None}
    for phase, path, key in (("attack", "/ws-push-attack", "payload"),
                             ("benign", "/ws-push-benign", "benign")):
        connection = None
        try:
            connection, status, leftover = ws_open(host, port, f"ws-push-{phase}", path=path)
            result["status"] = result["status"] or status
            if status != 101:
                continue
            reader = WSReader(connection, leftover)
            opcode, _, data = reader.read_frame()
            if opcode == 0x8:
                if phase == "attack":
                    result["blocked"] = True
                    result["close_code"] = int.from_bytes(data[:2], "big")
            elif opcode == 0x1:
                result[key] = data.decode("utf-8", errors="replace")
        except (OSError, ValueError) as error:
            result["error"] = str(error)
        finally:
            if connection is not None:
                connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result



H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(frame_type, flags, stream_id, payload):
    return (len(payload).to_bytes(3, "big") + bytes([frame_type, flags])
            + (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload)


def h2_header_block(case_id, path="/health"):
    block = bytearray(b"\x82\x87")
    block += b"\x44" + bytes([len(path)]) + path.encode("ascii")
    block += b"\x41" + bytes([len(b"app.test")]) + b"app.test"
    name = b"x-kunato-lab-case"
    value = case_id.encode("ascii")
    block += b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value
    return bytes(block)


def h2_connect(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=4)
    connection = context.wrap_socket(raw, server_hostname=host)
    if connection.selected_alpn_protocol() != "h2":
        connection.close()
        raise ValueError("ALPN did not select h2")
    connection.settimeout(4)
    connection.sendall(H2_PREFACE)
    connection.sendall(h2_frame(0x4, 0, 0, b""))
    connection.sendall(h2_frame(0x4, 0x1, 0, b""))
    return connection


def h2_read_frame(connection):
    head = recv_exact(connection, 9)
    length = int.from_bytes(head[:3], "big")
    frame_type = head[3]
    flags = head[4]
    stream = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
    payload = recv_exact(connection, length) if length else b""
    return frame_type, flags, stream, payload


def h2_wait_headers(connection, stream_id=1, limit=64):
    for _ in range(limit):
        frame_type, _, stream, _ = h2_read_frame(connection)
        if frame_type == 0x1 and stream == stream_id:
            return True
        if frame_type == 0x7:
            return False
        if frame_type == 0x3 and stream == stream_id:
            return False
    return False


def h2_normal(host, port, case_id):
    connection = None
    result = {"ok": False, "case": case_id}
    try:
        connection = h2_connect(host, port)
        connection.sendall(h2_frame(0x1, 0x5, 1, h2_header_block(case_id)))
        result["ok"] = h2_wait_headers(connection)
    except (OSError, ValueError, ssl.SSLError) as error:
        result["error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    return result


def h2_attack(host, port, case):
    result = {"case": case, "attack_closed": False, "normal": False}
    connection = None
    try:
        connection = h2_connect(host, port)
        if case == "rapid-reset":
            for index in range(50):
                stream = 1 + index * 2
                connection.sendall(h2_frame(
                    0x1, 0x4, stream, h2_header_block(f"h2-rapid-reset-{index}")))
                connection.sendall(h2_frame(0x3, 0, stream, b"\x00\x00\x00\x08"))
        elif case == "continuation":
            block = h2_header_block("h2-continuation")
            connection.sendall(h2_frame(0x1, 0, 1, block[:8]))
            for _ in range(64):
                connection.sendall(h2_frame(0x9, 0, 1, b"\x82" * 1024))
        elif case == "hpack":
            connection.sendall(h2_frame(0x1, 0x4, 1, b"\x82" * 16000))
        else:
            raise ValueError("unknown h2 case")
        connection.settimeout(1)
        try:
            frame_type, _, _, _ = h2_read_frame(connection)
            result["attack_closed"] = frame_type == 0x7
        except (OSError, ValueError):
            result["attack_closed"] = True
    except (OSError, ValueError, ssl.SSLError) as error:
        result["attack_error"] = str(error)
    finally:
        if connection is not None:
            connection.close()
    normal = h2_normal(host, port, f"h2-{case}-normal")
    result["normal"] = normal.get("ok", False)
    result["normal_error"] = normal.get("error")
    return result


def h2_probe(case, host, port, case_id=None):
    if case == "normal":
        return h2_normal(host, port, case_id or "h2-normal")
    return h2_attack(host, port, case)


def burst(count, host="app.test", port=8080):
    statuses = []
    for _ in range(count):
        result = request({"id": "burst", "method": "GET", "target": "/health"},
                         host, port)
        statuses.append(result.get("status") if result.get("status") is not None
                        else result.get("error"))
    return {"id": "burst", "statuses": statuses,
            "ok": sum(1 for status in statuses if status == 200),
            "limited": sum(1 for status in statuses if status in (429, 503)),
            "errors": sum(1 for status in statuses if not isinstance(status, int))}


def isolation(hosts, addresses):
    failures = []
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(line.split()[1] == "00000000" for line in routes):
        failures.append("IPv4 default route is present")
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(line.split()[0] == "0" * 32 and line.split()[1] == "00"
           and line.split()[-1] != "lo" for line in routes6):
        failures.append("IPv6 default route is present")
    for host in hosts:
        try:
            socket.getaddrinfo(host, 80)
            failures.append(f"Protected runner can resolve {host} directly")
        except socket.gaierror:
            pass
    for address in addresses:
        for port in (80, 8080, 3306):
            try:
                connection = socket.create_connection((address, port), timeout=1)
            except OSError:
                continue
            connection.close()
            failures.append(f"Protected runner can reach {address}:{port} directly")
            break
    return {"isolation_ok": not failures, "failures": failures}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["health", "cases", "raw", "slow", "slow-body",
                                          "slow-read", "exhaustion", "hold", "connect",
                                          "upstream", "ban", "ws-lifecycle", "ws-payload",
                                          "ws-push", "h2", "burst", "isolation", "metrics"])
    parser.add_argument("--path", default="/health")
    parser.add_argument("--status", type=int, default=200)
    parser.add_argument("--nonce")
    parser.add_argument("--host", default="app.test")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--length", type=int, default=16)
    parser.add_argument("--forbidden-host", action="append", default=[])
    parser.add_argument("--forbidden-ip", action="append", default=[])
    parser.add_argument("--cases", default="/lab/cases/smoke.json")
    parser.add_argument("--connections", type=int, default=8)
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--hold", type=float, default=2.0)
    parser.add_argument("--h2-case", default="normal")
    parser.add_argument("--case-id")
    args = parser.parse_args()
    if args.mode == "cases":
        for case in json.loads(Path(args.cases).read_text()):
            print(json.dumps(request(case, args.host, args.port)), flush=True)
    elif args.mode == "raw":
        for case in json.loads(Path(args.cases).read_text()):
            print(json.dumps(raw_request(case, args.host, args.port)), flush=True)
    elif args.mode == "slow":
        result = slow_request({"connections": args.connections, "hold_seconds": args.hold},
                              args.host, args.port)
        print(json.dumps(result))
        return int("error" in result)
    elif args.mode == "slow-body":
        result = slow_body({"hold_seconds": args.hold, "length": args.length},
                           args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "slow-read":
        result = slow_read({"hold_seconds": args.hold}, args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "exhaustion":
        result = exhaustion({"connections": args.connections}, args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "hold":
        result = hold_connections({"connections": args.connections,
                                   "hold_seconds": args.hold}, args.host, args.port)
        print(json.dumps(result))
        return int("error" in result)
    elif args.mode == "connect":
        result = connect(args.host, args.port)
        print(json.dumps(result))
        return int(not result["connected"])
    elif args.mode == "upstream":
        result = slow_upstream(args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "ban":
        result = ban_recovery({"requests": args.requests, "hold_seconds": args.hold},
                              args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "ws-lifecycle":
        result = websocket_lifecycle(args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "ws-payload":
        result = ws_payload(args.host, args.port)
        print(json.dumps(result))
        return int("error" in result)
    elif args.mode == "ws-push":
        result = ws_push(args.host, args.port)
        print(json.dumps(result))
        return int("error" in result)
    elif args.mode == "h2":
        result = h2_probe(args.h2_case, args.host, args.port, args.case_id)
        print(json.dumps(result))
        return int("error" in result)
    elif args.mode == "burst":
        result = burst(args.requests, args.host, args.port)
        print(json.dumps(result))
        return 0
    elif args.mode == "health":
        result = request({"id": "health", "method": "GET", "target": args.path},
                         args.host, args.port)
        print(json.dumps(result))
        ok = not result.get("error") and result.get("status") == args.status
        if args.nonce:
            ok = ok and result.get("origin") == args.nonce
        return int(not ok)
    elif args.mode == "isolation":
        result = isolation(args.forbidden_host, args.forbidden_ip)
        print(json.dumps(result))
        return int(not result["isolation_ok"])
    else:
        result = request({"id": "metrics", "method": "GET", "target": "/metrics"},
                         "127.0.0.1", 9090)
        print(json.dumps(result))
        return int("error" in result or result.get("status") != 200)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
