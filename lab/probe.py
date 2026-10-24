"""One-shot HTTP probes in a front-only or short-lived control container."""

import argparse
import hashlib
import http.client
import json
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
    parser.add_argument("mode", choices=["health", "cases", "isolation", "metrics"])
    parser.add_argument("--path", default="/health")
    parser.add_argument("--status", type=int, default=200)
    parser.add_argument("--nonce")
    parser.add_argument("--host", default="app.test")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--forbidden-host", action="append", default=[])
    parser.add_argument("--forbidden-ip", action="append", default=[])
    args = parser.parse_args()
    if args.mode == "cases":
        for case in json.loads(Path("/lab/cases/smoke.json").read_text()):
            print(json.dumps(request(case)), flush=True)
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
