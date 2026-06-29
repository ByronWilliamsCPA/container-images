"""Tests for scripts/verify_approved_lock.py.

Covers the A3 exit-gate core: schema conformance to the producer field set,
the source==target digest provenance invariant, digest format, cross-reference
of each lock id against catalog/images.yaml, ghcr_ref consistency, duplicate
ids, and a deliberately tampered-lock case that must fail validation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from verify_approved_lock import validate  # noqa: E402

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def minimal_entry(**overrides) -> dict:
    """One well-formed promotion entry, source_digest == target_digest."""
    base = {
        "id": "dhi-postgres-17",
        "ghcr_ref": "ghcr.io/byronwilliamscpa/dhi-postgres:17-debian13",
        "source_digest": DIGEST_A,
        "target_digest": DIGEST_A,
        "promoted_at": "2026-06-28T00:00:00Z",
        "promoted_by": "https://github.com/org/repo/actions/runs/1",
    }
    base.update(overrides)
    return base


def minimal_lock(*entries) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ApprovedImageLock",
        "metadata": {"last_updated": "2026-06-28T00:00:00Z"},
        "promoted": list(entries),
    }


def minimal_catalog(*ids_and_refs) -> dict:
    """Build an images.yaml-shaped catalog from (id, ghcr_name, ghcr_tag) tuples."""
    images = [{"id": i, "ghcr": {"name": n, "tag": t}} for (i, n, t) in ids_and_refs]
    return {"apiVersion": "v1", "images": images}


CATALOG = minimal_catalog(
    ("dhi-postgres-17", "dhi-postgres", "17-debian13"),
    ("dhi-redis-7", "dhi-redis", "7-debian13"),
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_empty_promoted_passes(self):
        assert validate(minimal_lock(), CATALOG) == []

    def test_single_valid_entry(self):
        assert validate(minimal_lock(minimal_entry()), CATALOG) == []

    def test_two_valid_entries(self):
        a = minimal_entry()
        b = minimal_entry(
            id="dhi-redis-7",
            ghcr_ref="ghcr.io/byronwilliamscpa/dhi-redis:7-debian13",
            source_digest=DIGEST_B,
            target_digest=DIGEST_B,
        )
        assert validate(minimal_lock(a, b), CATALOG) == []


# ---------------------------------------------------------------------------
# Missing required top-level fields
# ---------------------------------------------------------------------------


class TestMissingTopLevel:
    def test_missing_api_version(self):
        lock = minimal_lock(minimal_entry())
        del lock["apiVersion"]
        assert any("apiVersion" in e for e in validate(lock, CATALOG))

    def test_missing_promoted_key(self):
        lock = minimal_lock()
        del lock["promoted"]
        assert any("promoted" in e for e in validate(lock, CATALOG))

    def test_promoted_not_a_list(self):
        lock = minimal_lock()
        lock["promoted"] = {"not": "a list"}
        assert any("list" in e for e in validate(lock, CATALOG))

    def test_wrong_kind_rejected(self):
        lock = minimal_lock(minimal_entry())
        lock["kind"] = "SomethingElse"
        assert any("kind" in e for e in validate(lock, CATALOG))


# ---------------------------------------------------------------------------
# Missing required entry fields
# ---------------------------------------------------------------------------


class TestMissingEntryFields:
    @pytest.mark.parametrize(
        "field",
        [
            "id",
            "ghcr_ref",
            "source_digest",
            "target_digest",
            "promoted_at",
            "promoted_by",
        ],
    )
    def test_missing_field(self, field: str):
        entry = minimal_entry()
        del entry[field]
        errors = validate(minimal_lock(entry), CATALOG)
        assert any(field in e for e in errors), (
            f"Expected an error about missing field {field!r}, got: {errors}"
        )

    def test_entry_not_a_mapping(self):
        lock = minimal_lock()
        lock["promoted"] = ["not-a-mapping"]
        assert any("mapping" in e for e in validate(lock, CATALOG))


# ---------------------------------------------------------------------------
# Digest provenance invariant (the core A3 check)
# ---------------------------------------------------------------------------


class TestDigestInvariant:
    def test_source_target_mismatch_rejected(self):
        entry = minimal_entry(target_digest=DIGEST_B)
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("digest" in e for e in errors)

    def test_malformed_source_digest_rejected(self):
        entry = minimal_entry(
            source_digest="not-a-digest", target_digest="not-a-digest"
        )
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("source_digest" in e for e in errors)

    def test_short_digest_rejected(self):
        bad = "sha256:" + "a" * 10
        entry = minimal_entry(source_digest=bad, target_digest=bad)
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("source_digest" in e for e in errors)

    def test_uppercase_digest_rejected(self):
        bad = "sha256:" + "A" * 64
        entry = minimal_entry(source_digest=bad, target_digest=bad)
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("source_digest" in e for e in errors)


# ---------------------------------------------------------------------------
# Catalog cross-reference
# ---------------------------------------------------------------------------


class TestCatalogCrossReference:
    def test_id_not_in_catalog_rejected(self):
        entry = minimal_entry(
            id="dhi-ghost", ghcr_ref="ghcr.io/byronwilliamscpa/dhi-ghost:1"
        )
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("catalog" in e for e in errors)

    def test_ghcr_ref_mismatch_rejected(self):
        # id is in catalog, but ghcr_ref points somewhere the catalog never declared.
        entry = minimal_entry(ghcr_ref="ghcr.io/byronwilliamscpa/dhi-postgres:99-evil")
        errors = validate(minimal_lock(entry), CATALOG)
        assert any("ghcr_ref" in e for e in errors)


# ---------------------------------------------------------------------------
# Uniqueness and bypass-attempt cases
# ---------------------------------------------------------------------------


class TestUniquenessAndBypass:
    def test_duplicate_ids_detected(self):
        a = minimal_entry()
        b = minimal_entry(source_digest=DIGEST_B, target_digest=DIGEST_B)
        errors = validate(minimal_lock(a, b), CATALOG)
        assert any("duplicate" in e for e in errors)

    def test_tampered_lock_smuggles_unequal_digest(self):
        """A tampered entry swapping target_digest must fail the exit gate."""
        entry = minimal_entry(target_digest=DIGEST_B)
        errors = validate(minimal_lock(entry), CATALOG)
        assert errors, "Expected a tampered lock to fail validation"

    def test_tampered_lock_points_at_unapproved_image(self):
        """An entry for an image the catalog never approved must fail."""
        entry = minimal_entry(
            id="dhi-untrusted",
            ghcr_ref="ghcr.io/byronwilliamscpa/dhi-untrusted:1",
        )
        errors = validate(minimal_lock(entry), CATALOG)
        assert errors, "Expected an unapproved image id to fail validation"


# ---------------------------------------------------------------------------
# main() entry point and exit codes
# ---------------------------------------------------------------------------


class TestMainExitCodes:
    def _write(self, path: Path, data: object) -> None:
        with path.open("w") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)

    def _run_main(self, monkeypatch, lock_path: Path, catalog_path: Path) -> int:
        import verify_approved_lock as val

        monkeypatch.setattr(
            sys, "argv", ["verify_approved_lock.py", str(lock_path), str(catalog_path)]
        )
        with pytest.raises(SystemExit) as exc:
            val.main()
        code = exc.value.code
        return 0 if code is None else int(code)

    def test_main_passes_on_valid(self, tmp_path, monkeypatch):
        lock_p = tmp_path / "approved-lock.yaml"
        cat_p = tmp_path / "images.yaml"
        self._write(lock_p, minimal_lock(minimal_entry()))
        self._write(cat_p, CATALOG)
        assert self._run_main(monkeypatch, lock_p, cat_p) == 0

    def test_main_fails_on_invalid(self, tmp_path, monkeypatch):
        lock_p = tmp_path / "approved-lock.yaml"
        cat_p = tmp_path / "images.yaml"
        self._write(lock_p, minimal_lock(minimal_entry(target_digest=DIGEST_B)))
        self._write(cat_p, CATALOG)
        assert self._run_main(monkeypatch, lock_p, cat_p) == 1

    def test_main_missing_lock_file(self, tmp_path, monkeypatch):
        cat_p = tmp_path / "images.yaml"
        self._write(cat_p, CATALOG)
        assert self._run_main(monkeypatch, tmp_path / "nope.yaml", cat_p) == 2

    def test_main_missing_catalog_file(self, tmp_path, monkeypatch):
        lock_p = tmp_path / "approved-lock.yaml"
        self._write(lock_p, minimal_lock())
        assert self._run_main(monkeypatch, lock_p, tmp_path / "nope.yaml") == 2
