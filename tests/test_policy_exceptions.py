"""Guard tests for the exception lists in catalog/policies.yaml.

The loader (scripts/load_scanner_policy.py) fails safe: an exception with a bad
or missing ``expires`` silently suppresses nothing. These tests make such a
mistake fail in CI instead of being discovered when the gate blocks a mirror run.
Both lists are covered: ``exceptions`` (per CVE) and ``secret_exceptions`` (per
rule and exact path).
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
TICKET_RE = re.compile(
    r"^https://github\.com/ByronWilliamsCPA/container-images/issues/[0-9]+$"
)
SECRET_PATH_RE = re.compile(r"^/[A-Za-z0-9._@+=/-]+$")
# OpenSSF release gate: no vulnerability may be older than 60 days.
MAX_HORIZON = timedelta(days=60)
VALID_SCANNERS = {"trivy", "snyk", "both"}
CVE_KEYS = ("image_id", "cve_id", "scanner", "expires", "ticket", "justification")
SECRET_KEYS = ("image_id", "rule_id", "path", "expires", "ticket", "justification")


@pytest.fixture(scope="module")
def policy() -> dict:
    return yaml.safe_load((ROOT / "catalog" / "policies.yaml").read_text())


@pytest.fixture(scope="module")
def catalog_ids() -> set[str]:
    data = yaml.safe_load((ROOT / "catalog" / "images.yaml").read_text())
    return {entry["id"] for entry in data["images"]}


def _all_entries(policy: dict) -> list[tuple[str, dict]]:
    cves = [("exceptions", e) for e in policy["exceptions"]]
    secrets = [("secret_exceptions", e) for e in policy.get("secret_exceptions") or []]
    return cves + secrets


def _label(entry: dict) -> str:
    return f"{entry.get('image_id')} {entry.get('cve_id') or entry.get('path')}"


def test_every_exception_has_required_fields(policy: dict) -> None:
    for kind, entry in _all_entries(policy):
        keys = CVE_KEYS if kind == "exceptions" else SECRET_KEYS
        for key in keys:
            value = entry.get(key)
            # A YAML null must not pass: str(None) is the non-empty string "None".
            assert value is not None, f"{_label(entry)}: {key} is null or missing"
            assert str(value).strip(), f"{_label(entry)}: {key} is blank"


def test_exceptions_reference_known_images(policy: dict, catalog_ids: set[str]) -> None:
    used = {e["image_id"] for _, e in _all_entries(policy)}
    assert not used - catalog_ids, f"not in the catalog: {sorted(used - catalog_ids)}"


def test_exceptions_are_unique(policy: dict) -> None:
    cve_keys = [(e["image_id"], e["cve_id"]) for e in policy["exceptions"]]
    assert len(cve_keys) == len(set(cve_keys))
    secrets = policy.get("secret_exceptions") or []
    secret_keys = [(e["image_id"], e["rule_id"], e["path"]) for e in secrets]
    assert len(secret_keys) == len(set(secret_keys))


def test_exception_scanner_is_valid(policy: dict) -> None:
    assert {str(e["scanner"]).lower() for e in policy["exceptions"]} <= VALID_SCANNERS


def test_exception_tickets_name_an_issue_in_this_repo(policy: dict) -> None:
    for _, entry in _all_entries(policy):
        ticket = str(entry["ticket"])
        # A bare ".../issues/" prefix does not identify a tracking issue.
        assert TICKET_RE.match(ticket), f"{_label(entry)}: bad ticket {ticket!r}"


def test_secret_exceptions_name_one_exact_absolute_path(policy: dict) -> None:
    for entry in policy.get("secret_exceptions") or []:
        path = str(entry["path"])
        assert SECRET_PATH_RE.match(path), f"{_label(entry)}: not an exact path"
        assert ".." not in path.split("/"), f"{_label(entry)}: path traversal"


def test_exception_expiry_parses_and_stays_inside_the_horizon(policy: dict) -> None:
    updated = date.fromisoformat(str(policy["metadata"]["last_updated"]))
    for _, entry in _all_entries(policy):
        expires = date.fromisoformat(str(entry["expires"]))
        assert expires <= updated + MAX_HORIZON, (
            f"{_label(entry)} expires {expires}, more than "
            f"{MAX_HORIZON.days} days after last_updated {updated}"
        )
