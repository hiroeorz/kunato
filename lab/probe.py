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


def isolation(origin_ip):
    failures = []
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    if any(line.split()[1] == "00000000" for line in routes):
        failures.append("IPv4 default route is present")
    routes6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    if any(line.split()[0] == "0" * 32 and line.split()[1] == "00"
           and line.split()[-1] != "lo" for line in routes6):
        failures.append("IPv6 default route is present")
    try:
        socket.getaddrinfo("origin", 8080)
        failures.append("Protected runner can resolve origin directly")
    except socket.gaierror:
        pass
    try:
        connection = socket.create_connection((origin_ip, 8080), timeout=1)
    except OSError:
        pass
    else:
        connection.close()
        failures.append("Protected runner can reach the origin IP directly")
    return {"isolation_ok": not failures, "failures": failures}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["health", "cases", "isolation", "metrics"])
    parser.add_argument("--origin-ip")
    args = parser.parse_args()
    if args.mode == "cases":
        for case in json.loads(Path("/lab/cases/smoke.json").read_text()):
            print(json.dumps(request(case)), flush=True)
    elif args.mode == "isolation":
        if not args.origin_ip:
            parser.error("isolation requires --origin-ip")
        result = isolation(args.origin_ip)
        print(json.dumps(result))
        return int(not result["isolation_ok"])
    else:
        metrics = args.mode == "metrics"
        result = request({"id": args.mode, "method": "GET",
                          "target": "/metrics" if metrics else "/health"},
                         "127.0.0.1" if metrics else "app.test", 9090 if metrics else 8080)
        print(json.dumps(result))
        return int("error" in result or result.get("status") != 200)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
