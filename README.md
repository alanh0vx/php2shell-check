# php2shell-check

Quick vulnerability checker for **CVE-2026-109618** & **CVE-2026-109619** (PHP2Shell) — the pre-auth RCE in PHP core disclosed October 2026.

**Safe by default.** With no flags the tool is **passive**: it reads `Server` / `X-Powered-By` banners and compares the advertised PHP version against the upstream fixed releases. It sends no exploit probes. A behavioral check that sends the publicly-documented Stage-1 OOM trigger is available behind `--active` — it prints a warning and asks for confirmation first.

## Affected versions

Every PHP release from **5.4** (2012) through **8.4.26** on both `mod_php` and `PHP-FPM`. Both CVEs are rated **Critical (CVSS 9.2)**, pre-authentication, and were demonstrated as RCE against stock WordPress, Drupal, and Joomla.

## Usage

```bash
# No dependencies — Python 3.8+ standard library only

# Passive (default): banner check only, no exploit probes
python3 check_vuln.py https://your-app.example.com/index.php

# Machine-readable output + exit codes (0 ok / 1 vulnerable / 2 usage / 3 unknown)
python3 check_vuln.py https://your-app.example.com --json

# Active: send the Stage-1 OOM trigger and classify the response (invasive;
# asks for confirmation unless --yes)
python3 check_vuln.py https://your-app.example.com/wp-login.php --active
```

### Passive mode (default)

Sends `HEAD` (falls back to `GET` on 405/501) and reads `Server` / `X-Powered-By` only. It never sends the trigger. Classification follows the upstream fixed releases:

| Result | Exit | Meaning |
|--------|------|---------|
| **OK** | `0` | Advertised version meets a fixed release (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). **This describes the advertised version only** — the installed build is not verified, and distro backports are invisible to banners. |
| **POTENTIALLY VULNERABLE** | `1` | Advertised version is below its branch's fix, or the branch (5.4–8.1) no longer receives fixes. |
| **UNKNOWN** | `3` | Version hidden, unrecognized, or a prerelease (`dev`/`alpha`/`beta`/`rc`). |

If several banners advertise different versions (e.g. proxy + backend), the tool prefers a warning over a reassuring banner — an `ok` banner never masks a vulnerable one.

Behind Cloudflare? Passive mode works as-is (origin headers pass through the edge by default). `--cloudflare` is accepted here as a no-op — there is no payload to preset; run `--active --cloudflare` for a behavioral check.

### Active mode (`--active`)

Sends the publicly-documented Stage-1 OOM trigger — a multipart header-bomb over chunked transfer encoding — and classifies the response. This is strong behavioral evidence, but **invasive**: on a vulnerable server this is the exploit's first stage. It can recycle PHP workers and leave request state corrupted. The tool prints a warning and requires confirmation; `--yes` skips the prompt for scripting (refused on non-interactive runs without it).

```
python3 check_vuln.py <url> --active [--yes] [--timeout 10]
                          [--parts 1] [--headers 300000] [--no-chunk]
                          [--strategy concentrated|spread] [--cloudflare]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--parts` | 1 | Multipart parts in the payload |
| `--headers` | 300000 | Header lines total (~3.9 MiB on the wire) |
| `--no-chunk` | off | Send with `Content-Length` instead of chunked TE (use if the server returns HTTP 400) |
| `--strategy` | concentrated | `spread` distributes headers across parts (for proxies that limit per-part MIME headers) |
| `--cloudflare` | off | Preset: `--no-chunk --strategy spread --parts 100` (also accepted in passive mode as a no-op) |

The payload flags (`--parts`, `--headers`, `--no-chunk`, `--strategy`) are rejected with exit `2` without `--active` — passive mode has no payload to shape.

Active-mode verdicts:

| Verdict | Exit | Meaning |
|---------|------|---------|
| **VULNERABLE** | `1` | OOM fatal signature confirmed in the response body — PHP is unpatched |
| **LIKELY VULNERABLE** | `1` | HTTP 500 (`display_errors=Off` hides the OOM text) or HTTP 502 (FPM child crashed) |
| **POSSIBLY VULNERABLE** | `1` | HTTP 200 but advertised version is in the vulnerable range; a proxy may have blocked the trigger |
| **NOT VULNERABLE** | `0` | Trigger delivered and handled normally, and the advertised version meets a fixed release. Advertised only — the installed build is not verified |
| **PATCHED OR BLOCKED** | `3` | Trigger handled normally but no version disclosed — cannot rule out a proxy absorbing it |
| **INCONCLUSIVE / BLOCKED** | `3` | Proxy/WAF rejected the request (try `--no-chunk`, `--cloudflare`, or test the PHP port directly) |

### Example output (passive)

```
PHP2Shell Vulnerability Checker
CVE-2026-109618 / CVE-2026-109619
passive mode — banner check only, no exploit probes

  Results
  ──────────────────────────────────────────────────
  Target:       http://vulnerable-server/index.php
  Banners:      Apache/2.4.69 (Debian)
                PHP/8.4.26
  PHP version:  8.4.26

  ■ POTENTIALLY VULNERABLE
    PHP 8.4.26: potentially vulnerable — below the upstream fixed release
    for its branch (8.4.27). HTTP headers cannot tell whether this version
    contains a backported fix.

  Action required:
    Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ and restart all PHP workers.

  Stronger evidence: re-run with --active (sends the Stage-1 trigger — invasive).
```

### Important notes

- **Headers are not proof.** Banners can be spoofed, hidden, or lag behind the real binary. `OK` means the *advertised* version meets an upstream fix — a distro backport with an unchanged version string looks identical to a vulnerable one. Server-side checks (`php -v`, package manager) are stronger evidence.
- **Behind nginx?** Nginx typically buffers the request and re-adds `Content-Length`, which lets PHP's `post_max_size` check reject the body before the amplifier fires. In active mode, a `200` behind nginx may mean the proxy blocked the trigger, not that PHP is patched.
- **Authorization.** Active mode sends a ~4 MiB payload that forces a memory-limit fatal on vulnerable targets. Only run it against systems you own or have explicit authorization to test.

## How the trigger works (active mode)

The technique is fully public (Calif.io, Wiz Research, October 2026):

1. **Chunked Transfer Encoding** — the request carries no `Content-Length`, so PHP's `post_max_size` check is skipped.
2. **Header amplification** — one multipart part with ~300,000 header lines. PHP retains ~320 bytes of heap per header line, so ~3.9 MiB on the wire drives ~96 MiB of allocation, blowing a 64 MiB `memory_limit`.
3. **The OOM fires during request-startup parsing** (`"Unknown on line 0"`), before any application code runs. On unpatched PHP this leaves dangling pointers that the CVEs exploit.

The tool only sends the trigger and reads the response — it does not attempt to exploit the dangling state.

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
- Version-semantics reference: [openai/php2shell-checker](https://github.com/openai/php2shell-checker)

Full reproducible lab (vulnerable + patched victims, demos, RCE chain):
[alanh0vx/php2shell-lab](https://github.com/alanh0vx/php2shell-lab)

## Disclaimer

Run this only against systems you own or have explicit authorization to test. This tool is provided for defensive security assessment. The authors are not responsible for misuse.

## License

MIT
