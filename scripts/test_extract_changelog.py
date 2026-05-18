"""Tests for scripts/extract_changelog.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from extract_changelog import extract  # noqa: E402


_FIXTURE = """\
# Changelog

## [Unreleased]

### Added
- pending work

## [5.0.0] - 2026-03-25

### Added
- LTPAnchorRegistry v5 deployed

### Changed
- **[BREAKING]** Contract version 4 → 5

## [4.0.0] - 2026-03-25

### Added
- 84 Solidity tests
"""


def test_extract_existing_version():
    body = extract(_FIXTURE, "v5.0.0")
    assert body is not None
    assert "LTPAnchorRegistry v5 deployed" in body
    assert "84 Solidity tests" not in body  # next section excluded


def test_extract_strips_leading_blank_lines():
    body = extract(_FIXTURE, "v5.0.0")
    assert body.splitlines()[0] == "### Added"


def test_extract_strips_trailing_blank_lines():
    body = extract(_FIXTURE, "v5.0.0")
    assert body.splitlines()[-1].strip()


def test_extract_without_v_prefix():
    body = extract(_FIXTURE, "5.0.0")
    assert body is not None
    assert "LTPAnchorRegistry v5 deployed" in body


def test_extract_missing_version_returns_none():
    assert extract(_FIXTURE, "v9.9.9") is None


def test_extract_unreleased_section():
    body = extract(_FIXTURE, "Unreleased")
    assert body is not None
    assert "pending work" in body
