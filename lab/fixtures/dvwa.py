"""Initialize the disposable DVWA fixture and verify its SQLi page.

The fixture runs with authentication disabled and the low security level.
The controller seeds a separate canary table after this script returns; this
script only proves that the setup and the vulnerable endpoint are usable.
"""

import argparse
import http.client
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence import USER_AGENT  # noqa: E402


def request(host, port, method, target, body=None, headers=None):
    connection = http.client.HTTPConnection(host, port, timeout=5)
    request_headers = {"User-Agent": USER_AGENT, "Connection": "close", **(headers or {})}
    connection.request(method, target, body=body, headers=request_headers)
    response = connection.getresponse()
    content = response.read(65536).decode("utf-8", errors="replace")
    response_headers = response.getheaders()
    connection.close()
    return response.status, response_headers, content


def cookies_from(headers):
    cookies = []
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0].strip()
        if "=" in pair:
            cookies.append(pair)
    return "; ".join(cookies)


def wait_for_setup(host, port, timeout):
    deadline = time.monotonic() + timeout
    while True:
        try:
            status, headers, content = request(host, port, "GET", "/setup.php")
            if status == 200:
                return headers, content
        except (OSError, http.client.HTTPException):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("DVWA setup page did not become ready")
        time.sleep(0.2)


def setup(base, timeout, auth=False):
    parsed = urlsplit(base)
    host = parsed.hostname
    port = parsed.port or 80
    headers, content = wait_for_setup(host, port, timeout)
    match = re.search(r"name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"]", content)
    if not match:
        raise RuntimeError("DVWA setup token is missing")
    cookie = cookies_from(headers)
    if not cookie:
        raise RuntimeError("DVWA setup did not set a session cookie")
    body = urlencode({"create_db": "Create / Reset Database", "user_token": match.group(1)})
    status, _, content = request(
        host, port, "POST", "/setup.php", body,
        {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
    )
    if status not in (200, 302):
        raise RuntimeError(f"DVWA setup returned status {status}")
    if status == 200 and "Database has been created" not in content:
        raise RuntimeError("DVWA setup did not report a created database")
    setup_status = status
    auth_status = None
    if auth:
        body = urlencode({"username": "admin", "password": "password", "Login": "Login"})
        status, headers, _ = request(
            host, port, "POST", "/login.php", body,
            {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie},
        )
        if status not in (200, 302):
            raise RuntimeError(f"DVWA login returned status {status}")
        renewed = cookies_from(headers)
        if renewed:
            cookie = renewed
        auth_status = status
    status, _, content = request(
        host, port, "GET", "/vulnerabilities/sqli/?id=1&Submit=Submit",
        headers={"Cookie": cookie},
    )
    if status != 200 or "First name" not in content:
        raise RuntimeError("DVWA SQL injection page is not usable after setup")
    return {"status": "ok", "setup_status": setup_status, "auth_status": auth_status,
            "sqli_status": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["setup"])
    parser.add_argument("--base", default="http://dvwa")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--auth", action="store_true")
    args = parser.parse_args()
    try:
        result = setup(args.base, args.timeout, args.auth)
    except (OSError, RuntimeError, http.client.HTTPException) as error:
        print(json.dumps({"status": "error", "error": str(error)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
