"""CLI: python3 -m phpatchscan <url> [more urls...]

Prints one JSON verdict object per URL.

Exit codes: 0 — no actionable finding; 1 — at least one target is
vulnerable, possibly vulnerable, or on an end-of-life branch;
2 — usage error, or a target could not be scanned at all.
"""

import json
import sys

from .scan import scan

_ACTIONABLE = ("vulnerable", "possibly_vulnerable", "eol")


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    worst = 0
    for url in argv:
        try:
            r = scan(url)
            print(json.dumps(r, indent=1))
            if (r.get("verdict") or {}).get("status") in _ACTIONABLE:
                worst = max(worst, 1)
        except Exception as e:  # one bad target must not kill the run
            print(json.dumps({"url": url, "error": str(e)}))
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
