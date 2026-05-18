#!/usr/bin/env python3
"""Extract the CHANGELOG.md section for a given semver tag.

Usage:
    scripts/extract_changelog.py v5.0.0 [--changelog CHANGELOG.md]

Prints the section body (between `## [5.0.0] - …` and the next `## [`)
to stdout. Exit 0 on success, 1 if the section is not found.

Used by `.github/workflows/release.yml` to populate the GitHub Release
body from CHANGELOG.md without parsing git log.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


_SECTION_RE = re.compile(r"^##\s+\[([^\]]+)\]")


def extract(changelog: str, version: str) -> str | None:
    """Return the body for `version` (without the heading line), or None."""
    target = version.lstrip("v")
    lines = changelog.splitlines()
    out: list[str] = []
    in_section = False
    for line in lines:
        m = _SECTION_RE.match(line)
        if m:
            if in_section:
                # Reached the next section — stop.
                break
            if m.group(1) == target:
                in_section = True
                continue  # skip the heading itself
        if in_section:
            out.append(line)
    if not in_section:
        return None
    # Trim leading / trailing blank lines for a clean release body.
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("version", help="Tag like v5.0.0")
    p.add_argument(
        "--changelog",
        type=Path,
        default=Path("CHANGELOG.md"),
        help="Path to CHANGELOG.md (default: CHANGELOG.md)",
    )
    args = p.parse_args(argv)
    if not args.changelog.exists():
        print(f"error: changelog not found at {args.changelog}", file=sys.stderr)
        return 1
    body = extract(args.changelog.read_text(encoding="utf-8"), args.version)
    if body is None:
        print(
            f"error: section for {args.version} not found in {args.changelog}",
            file=sys.stderr,
        )
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
