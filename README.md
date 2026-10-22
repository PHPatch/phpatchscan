# phpatchscan — free external PHP vulnerability scanner

The open-source scanner behind [phpatch.com](https://phpatch.com).
It answers one question about any public website: **is its PHP
runtime below the fixed release for a known critical advisory**
(starting with php2shell, CVE-2026-109618 / CVE-2026-109619)?

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#what-it-does)
[![Tests](https://github.com/PHPatch/phpatchscan/actions/workflows/tests.yml/badge.svg)](https://github.com/PHPatch/phpatchscan/actions/workflows/tests.yml)

## What it does

- **Passive fingerprinting plus limited path checks.** It reads response headers,
  generator tags and other signals a site already discloses
  publicly, and checks for a publicly exposed phpinfo page.
- **Honest verdicts.** `vulnerable`, `patched`, `eol` (branch with
  no fix), `possibly_vulnerable` (a distribution build below a
  floor — a check signal, since distros backport fixes),
  `not_assessed` (branch newer than the advisory database) — or
  `indeterminate` when the site hides its version.
  Most well-run sites hide it; we say so instead of guessing.
- **No exploit probes, ever.** Nothing in this tool attempts to
  trigger a vulnerability.
- **Public targets only.** The fetcher refuses loopback, private
  and link-local addresses (including cloud metadata endpoints),
  non-HTTP(S) schemes and ports other than 80/443, pins the
  validated IP, and re-validates every redirect — it is designed
  so it cannot be pointed at internal services. The refusals are
  exercised by the test suite in `tests/` on every push.
- **Zero dependencies.** Python 3.11+ standard library only.

## How it compares

The php2shell scanners that appeared in October 2026 differ
mostly in **how they decide you are vulnerable** — and in whether
they try to trigger the bug to find out:

| Tool | Detection | Sends exploit triggers? | Remediation | License |
|---|---|---|---|---|
| **phpatchscan** (this repo) | Version fingerprint from what the site discloses; says "version hidden" instead of guessing | **No — never** | Via [PHP Patch Assurance](https://phpatch.com): snapshot-first patch, verify, rollback, evidence report | MIT |
| OpenAI php2shell-checker | Version fingerprint from `X-Powered-By` / `Server` headers only | No | None | Apache-2.0 |
| Searchlight Cyber php2shell-scanner | Behavioral — crafted multipart probes force PHP out of memory and watch for the crash | **Yes, deliberately** | None | No LICENSE file |
| SamJUK php2shell-check | Behavioral, local — observes how the installed PHP binary terminates at its memory limit | Only against a throwaway local CLI process | None | MIT |
| squiblyza php_vuln_scan | Version fingerprint from headers/markup, plus version-disclosure hunting | No | None | MIT |
| JoasASantos php2shell-scanner | Version fingerprint + subdomain recon + origin scan | Optional opt-in probe (README warns of DoS risk) | None | README states MIT; no LICENSE file |

Full criteria, the fairness notes (behavioral checks catch
backports; crash signals also misfire on some patched builds),
SSRF-safety comparison and an FAQ:
**[PHP vulnerability scanners compared](https://phpatch.com/compare)**.

## Install

```bash
git clone https://github.com/PHPatch/phpatchscan.git
cd phpatchscan
# Python 3.11+ standard library only — no pip install, no dependencies.
```

## Run it

From the clone, run it right there — no install step:

```bash
python3 -m phpatchscan https://your-site.com
```

Prefer a zip? Download `phpatchscan.zip` from phpatch.com, then
either install it and run from anywhere:

```bash
python3 -m pip install phpatchscan.zip
python3 -m phpatchscan https://your-site.com
```

or unzip and run in place:

```bash
unzip phpatchscan.zip
cd phpatchscan
python3 -m phpatchscan https://your-site.com
```

Output is one JSON object per URL: the verdict, the disclosed PHP
version and where it was disclosed, and CMS fingerprints.

Exit codes (for scripts and CI): **0** — scanned, no actionable
finding; **1** — at least one target is `vulnerable`,
`possibly_vulnerable`, or on an end-of-life branch; **2** — usage
error, or a target could not be judged at all: unreachable, or
`not_assessed` (its PHP branch is newer than the advisory
database, so the scanner cannot judge it). With several targets,
the worst code wins.

Prefer a browser? The same scan runs free at
[phpatch.com](https://phpatch.com) and includes a PDF report.

## What it is not

The external scan cannot see servers that hide their version. The
full PHP Patch Assurance adds a read-only on-server deep check,
one-click snapshot-first patching with a restore-tested safety net,
automatic revert on failure, verified rollback, and a work report with a SHA-256
integrity hash: [phpatch.com](https://phpatch.com).

## Authorized use

Only scan sites you own or have permission to scan. The hosted
scanner at phpatch.com additionally enforces rate limits and an
opt-out blocklist for site operators (see the Terms, section 8).

## Advisory data

`phpatchscan/data/cves.json` is the advisory database the scanner
judges against — branch floors, fixed releases, references and the
leak/exploitation timeline. Last updated 2026-10-22. Update
process: floors are reviewed against the php.net release
announcements on every PHP security release and at least monthly.
Corrections are welcome as pull requests; every change to this
file requires maintainer review (see CODEOWNERS), because it
changes the verdicts the scanner gives.

A verdict of `patched` means only that the disclosed version is
not below the fixed releases in this database — it is not a
general security guarantee. A version below a floor on a
distribution build (Ubuntu/Debian packages) is a "check" signal,
not proof: distros backport fixes without changing the upstream
version, and the scanner says so when it detects a distro build.

## License

MIT. Not affiliated with the PHP Group. PHP is a trademark of the
PHP Group.
