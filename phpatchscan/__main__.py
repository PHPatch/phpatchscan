"""CLI: python3 -m phpatchscan <url> [more urls...]

Prints one JSON verdict object per URL.
"""

import json
import sys

from .scan import scan


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    for url in argv:
        try:
            print(json.dumps(scan(url), indent=1))
        except Exception as e:  # one bad target must not kill the run
            print(json.dumps({"url": url, "error": str(e)}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
