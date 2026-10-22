# php2shell-check

Quick vulnerability checker for **CVE-2026-109618** & **CVE-2026-109619** (PHP2Shell) — the pre-auth RCE in PHP core disclosed October 2026.

**Detection only.** This tool sends the publicly-documented Stage-1 OOM trigger and reads the HTTP status code. It does not exploit anything, exfiltrate data, or plant anything on the target.

## Affected versions

Every PHP release from **5.4** (2012) through **8.4.26** on both `mod_php` and `PHP-FPM`. Both CVEs are rated **Critical (CVSS 9.2)**, pre-authentication, and were demonstrated as RCE against stock WordPress, Drupal, and Joomla.

## Usage

```bash
# No dependencies — Python 3.6+ standard library only
python3 check_vuln.py https://your-app.example.com/index.php
```

Any PHP endpoint works — `/wp-login.php`, `/index.php`, etc. The bug fires during request-startup parsing, before any application code runs.

### Options

```
python3 check_vuln.py <url> [-u <url>] [--timeout 10] [--headers 300000] [--parts 1] [--no-chunk]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | | Target URL (alternative to positional arg) |
| `--timeout` | 10 | HTTP timeout (seconds) |
| `--headers` | 300000 | Header lines per part (~3.9 MiB on the wire) |
| `--parts` | 1 | Multipart parts in the payload |
| `--no-chunk` | off | Send with `Content-Length` instead of chunked TE (use if server returns HTTP 400) |

### Example output

```
PHP2Shell Vulnerability Checker
CVE-2026-109618 / CVE-2026-109619 — detection only

  Target:   http://vulnerable-server/index.php
  Payload:  1 part(s) x 300,000 headers = ~92 MiB PHP heap
  Method:   chunked TE (bypasses post_max_size)

  Results
  ──────────────────────────────────────────────────
  HTTP status:  200
  PHP version:  8.4.26 (VULNERABLE)
  SAPI:         mod_php (Apache)
  Wire size:    3.9 MiB

  ■ VULNERABLE
    OOM fatal confirmed in response (HTTP 200). PHP is unpatched — the fatal
    fires during request-startup parsing, before any app code runs.

  Action required:
    Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+
    Then restart all PHP workers.
```

## Interpreting results

The checker uses **two signals**: the OOM error signature in the response body, and the PHP version from `X-Powered-By` / `Server` headers.

| Verdict | Meaning |
|---------|---------|
| **VULNERABLE** | OOM fatal error confirmed in response body — PHP is unpatched |
| **LIKELY VULNERABLE** | HTTP 500 but `display_errors=Off` hides the OOM text; version confirms vulnerable range |
| **LIKELY VULNERABLE (FPM)** | HTTP 502 — PHP-FPM child crashed (OOM fatal) |
| **POSSIBLY VULNERABLE** | HTTP 200 but detected PHP version is in the vulnerable range; a proxy may have blocked the trigger |
| **NOT VULNERABLE** | PHP version is patched (8.4.27+), or OOM trigger had no effect |
| **INCONCLUSIVE** | Cannot determine — proxy/WAF blocked the request (try `--no-chunk` or test directly) |

### Important notes

- **Behind nginx?** Nginx typically buffers the request and re-adds `Content-Length`, which lets PHP's `post_max_size` check reject the body before the amplifier fires. A `200` behind nginx may mean the proxy blocked the trigger, not that PHP is patched. Test against the PHP port directly if possible.
- **False negatives:** A reverse proxy, WAF, or CDN (Cloudflare, AWS ALB, etc.) can absorb the payload before it reaches PHP. A clean result behind infrastructure does not guarantee the PHP version is patched.
- **False positives:** Some applications return HTTP 500 for other reasons. The tool looks for the OOM signature (`memory` / `Unknown on line 0`) in the response body to reduce false positives, but `display_errors=Off` hides this.

## How it works

The technique is fully public (Calif.io, Wiz Research, October 2026):

1. **Chunked Transfer Encoding** — the request carries no `Content-Length`, so PHP's `post_max_size` check is skipped.
2. **Header amplification** — one multipart part with ~300,000 header lines. PHP retains ~320 bytes of heap per header line, so ~3.9 MiB on the wire drives ~96 MiB of allocation, blowing a 64 MiB `memory_limit`.
3. **The OOM fires during request-startup parsing** (`"Unknown on line 0"`), before any application code runs. On unpatched PHP this leaves dangling pointers that the CVEs exploit.

This tool only sends the trigger and reads the response — it does not attempt to exploit the dangling state.

## Fix

**Upgrade PHP.** It's the only complete fix.

| Branch | Patched version |
|--------|----------------|
| 8.2 | **8.2.35**+ |
| 8.3 | **8.3.36**+ |
| 8.4 | **8.4.27**+ |
| 8.5 | **8.5.12**+ |

Restart all workers after upgrading — the vulnerable state lives in running processes.

**Interim mitigations** (not a substitute for patching):
- `memory_limit=-1` (raises DoS risk)
- `session.upload_progress.enabled=0` (FPM only)
- Block multipart at the edge / cap headers-per-part at the reverse proxy
- WAF rules (Cloudflare, AWS, Akamai, etc. have shipped mitigations)

## References

- VXRL — [PHP2Shell](https://vxrl.medium.com/php2shell-bfa0d8db5e84)
- Calif.io — [php2shell](https://calif.io/php2shell/)
- Wiz Research — [PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- CVE-2026-109618 — [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- CVE-2026-109619 — [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

## Disclaimer

Run this only against systems you own or have explicit authorization to test. This tool is provided for defensive security assessment. The authors are not responsible for misuse.

## License

MIT
