"""One-shot HTTP probes in a front-only or short-lived control container."""

import argparse
import base64
import hashlib
import http.client
import json
import re
import socket
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


def ws_read_frame(connection):
    header = recv_exact(connection, 2)
    first, second = header
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(connection, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(connection, 8), "big")
    mask = recv_exact(connection, 4) if second & 0x80 else b""
    payload = recv_exact(connection, length)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first & 0x0F, bool(first & 0x80), payload


def websocket_lifecycle(host="app.test", port=8080):
    started = time.monotonic()
    connection = None
    result = {"id": "ws-lifecycle", "status": None, "pong": False,
              "echo": None, "closed": False}
    try:
        connection = socket.create_connection((host, port), timeout=4)
        key = base64.b64encode(b"kunato-lab-ws-key").decode()
        request = (f"GET /ws-lifecycle HTTP/1.1\r\nHost: app.test\r\n"
                   f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   f"X-Kunato-Lab-Case: ws-lifecycle\r\n\r\n")
        connection.sendall(request.encode("latin-1"))
        connection.settimeout(4)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        status, _ = status_of(data)
        result["status"] = status
        if status != 101:
            return result
        connection.sendall(ws_frame(0x9, b"ping"))
        opcode, _, payload = ws_read_frame(connection)
        result["pong"] = opcode == 0xA and payload == b"ping"
        connection.sendall(ws_frame(0x1, b"frag", fin=False))
        connection.sendall(ws_frame(0x0, b"ment", fin=False))
        connection.sendall(ws_frame(0x0, b"ed", fin=True))
        opcode, _, payload = ws_read_frame(connection)
        if opcode == 0x1:
            result["echo"] = payload.decode("utf-8", errors="replace")
        connection.sendall(ws_frame(0x8, b"\x03\xe8"))
        try:
            opcode, _, _ = ws_read_frame(connection)
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
                                          "slow-read", "exhaustion", "upstream", "ban",
                                          "ws-lifecycle", "isolation", "metrics"])
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
    args = parser.parse_args()
    if args.mode == "cases":
        for case in json.loads(Path(args.cases).read_text()):
            print(json.dumps(request(case)), flush=True)
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
