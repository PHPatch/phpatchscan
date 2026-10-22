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
  no fix) — or `indeterminate` when the site hides its version.
  Most well-run sites hide it; we say so instead of guessing.
- **No exploit probes, ever.** Nothing in this tool attempts to
  trigger a vulnerability.
- **Public targets only.** The fetcher refuses loopback, private
  and link-local addresses (including cloud metadata endpoints),
  non-HTTP(S) schemes and ports other than 80/443, pins the
  validated IP, and re-validates every redirect — it cannot be
  pointed at internal services.
- **Zero dependencies.** Python 3.11+ standard library only.

## Run it

```bash
python3 -m phpatchscan https://your-site.com
```

Output is one JSON object per URL: the verdict, the disclosed PHP
version and where it was disclosed, and CMS fingerprints.

Prefer a browser? The same scan runs free at
[phpatch.com](https://phpatch.com) and includes a PDF report.

## What it is not

The external scan cannot see servers that hide their version. The
full PHP Patch Service adds a read-only on-server deep check,
one-click snapshot-first patching with a restore-tested safety net,
automatic revert on failure, verified rollback, and a work report with a SHA-256
integrity hash: [phpatch.com](https://phpatch.com).

## Advisory data

`phpatchscan/data/cves.json` is the advisory database the scanner
judges against — branch floors, fixed releases, references and the
leak/exploitation timeline. Corrections welcome.

## License

MIT. Not affiliated with the PHP Group. PHP is a trademark of the
PHP Group.
