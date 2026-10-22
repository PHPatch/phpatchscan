# phpatchscan — free external PHP vulnerability scanner

The open-source scanner behind [phpatch.com](https://phpatch.com).
It answers one question about any public website: **is its PHP
runtime below the fixed release for a known critical advisory**
(starting with php2shell, CVE-2026-109618 / CVE-2026-109619)?

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

## Run it

Install from the zip (or from a clone of this repo), then run it
from anywhere:

```bash
python3 -m pip install phpatchscan.zip
python3 -m phpatchscan https://your-site.com
```

Or skip installing: unzip, step into the folder, and run it there:

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
full PHP Patch Service adds a read-only on-server deep check,
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
