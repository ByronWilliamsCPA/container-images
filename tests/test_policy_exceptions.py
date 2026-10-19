"""Guard tests for the CVE exception list in catalog/policies.yaml.

The loader (scripts/load_scanner_policy.py) fails safe: an exception with a bad
or missing ``expires`` silently suppresses nothing. These tests make such a
mistake fail in CI instead of being discovered when the gate blocks a mirror run.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
TICKET_PREFIX = "https://github.com/ByronWilliamsCPA/container-images/issues/"
# OpenSSF release gate: no vulnerability may be older than 60 days.
MAX_HORIZON = timedelta(days=60)
VALID_SCANNERS = {"trivy", "snyk", "both"}
REQUIRED_KEYS = ("image_id", "cve_id", "scanner", "expires", "ticket", "justification")


@pytest.fixture(scope="module")
def policy() -> dict:
    return yaml.safe_load((ROOT / "catalog" / "policies.yaml").read_text())


@pytest.fixture(scope="module")
def catalog_ids() -> set[str]:
    data = yaml.safe_load((ROOT / "catalog" / "images.yaml").read_text())
    return {entry["id"] for entry in data["images"]}


def test_every_exception_has_required_fields(policy: dict) -> None:
    for entry in policy["exceptions"]:
        for key in REQUIRED_KEYS:
            value = str(entry.get(key, "")).strip()
            assert value, f"{entry.get('cve_id')}: missing {key}"


def test_exceptions_reference_known_images(policy: dict, catalog_ids: set[str]) -> None:
    unknown = {e["image_id"] for e in policy["exceptions"]} - catalog_ids
    assert not unknown, f"exceptions for images not in the catalog: {sorted(unknown)}"


def test_exceptions_are_unique_per_image_and_cve(policy: dict) -> None:
    keys = [(e["image_id"], e["cve_id"]) for e in policy["exceptions"]]
    assert len(keys) == len(set(keys))


def test_exception_scanner_is_valid(policy: dict) -> None:
    assert {str(e["scanner"]).lower() for e in policy["exceptions"]} <= VALID_SCANNERS


def test_exception_tickets_point_at_this_repo(policy: dict) -> None:
    for entry in policy["exceptions"]:
        assert str(entry["ticket"]).startswith(TICKET_PREFIX), entry["cve_id"]


def test_exception_expiry_parses_and_stays_inside_the_horizon(policy: dict) -> None:
    updated = date.fromisoformat(str(policy["metadata"]["last_updated"]))
    for entry in policy["exceptions"]:
        expires = date.fromisoformat(str(entry["expires"]))
        assert expires <= updated + MAX_HORIZON, (
            f"{entry['image_id']} {entry['cve_id']} expires {expires}, more than "
            f"{MAX_HORIZON.days} days after last_updated {updated}"
        )
