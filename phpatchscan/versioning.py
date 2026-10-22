"""Version parsing and vulnerability verdicts.

A PHP build is judged against every advisory in data/cves.json. For each
advisory, supported branches have a fixed-release floor; anything older
is vulnerable, and any branch below the advisory's EOL line has no fix at
all (branch upgrade or offline are the only remedies).
"""

import json
import os
import re

_DATA = os.path.join(os.path.dirname(__file__), "data", "cves.json")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def load_advisories():
    with open(_DATA, encoding="utf-8") as f:
        return json.load(f)["advisories"]


def parse_version(text):
    """Extract the first x.y[.z] version from arbitrary text -> tuple|None."""
    if not text:
        return None
    m = _VERSION_RE.search(str(text))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def fmt(version):
    return ".".join(str(p) for p in version)


def branch_of(version):
    return f"{version[0]}.{version[1]}"


def verdict_for(version):
    """Return a verdict dict for one PHP version tuple.

    status: 'patched' | 'vulnerable' | 'eol' | 'unknown'
      patched    — at or above every advisory floor for its branch
      vulnerable — a patched release exists for its branch; it is below it
      eol        — branch is below an advisory's EOL line: no fix exists
      unknown    — version could not be determined
    """
    if version is None:
        return {"status": "unknown", "version": None, "branch": None,
                "detail": "PHP version could not be determined."}
    branch = branch_of(version)
    problems = []
    for adv in load_advisories():
        eol_below = parse_version(adv["eol_below"])
        if (version[0], version[1]) < (eol_below[0], eol_below[1]):
            return {"status": "eol", "version": fmt(version),
                    "branch": branch, "advisory": adv["id"],
                    "cves": adv["cves"],
                    "detail": (f"Branch {branch} is end-of-life for "
                               f"{adv['id']}: no patched release exists. "
                               "The php2shell vector can still be "
                               "closed with a configuration mitigation "
                               "(session.upload_progress.enabled = Off); "
                               "a branch upgrade remains the permanent "
                               "fix.")}
        floor_txt = adv["fixed_releases"].get(branch)
        if floor_txt is None:
            continue  # branch newer than the advisory knows — no finding
        floor = parse_version(floor_txt)
        if version < floor:
            problems.append({"advisory": adv["id"], "cves": adv["cves"],
                             "cvss_v4": adv.get("cvss_v4"),
                             "floor": floor_txt})
    if problems:
        p = problems[0]
        return {"status": "vulnerable", "version": fmt(version),
                "branch": branch, "advisory": p["advisory"],
                "cves": p["cves"], "cvss_v4": p.get("cvss_v4"),
                "floor": p["floor"],
                "detail": (f"PHP {fmt(version)} is below the patched "
                           f"release {p['floor']} for branch {branch} "
                           f"({', '.join(p['cves'])}).")}
    return {"status": "patched", "version": fmt(version), "branch": branch,
            "detail": f"PHP {fmt(version)} is at or above every patched "
                      "release floor for its branch."}


def fixed_tag_for(version, variant):
    """Official docker php image tag for the patched release of a branch.

    e.g. version (8,3,35), variant 'apache' -> 'php:8.3.36-apache'
    Returns None when no advisory floor applies.
    """
    v = verdict_for(version)
    if v["status"] == "vulnerable":
        return f"php:{v['floor']}-{variant}"
    if v["status"] == "patched":
        return f"php:{fmt(version)}-{variant}"
    return None
