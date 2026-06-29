"""Tests for scripts/validate_catalog_schema.py.

Covers: happy path, missing required fields, invalid enum values,
duplicate IDs, duplicate GHCR refs, and bypass-attempt cases where
an attacker tries to sneak an unapproved value through validation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import validate_catalog_schema  # noqa: E402
from validate_catalog_schema import validate  # noqa: E402


def load_fixture(name: str) -> dict:
    fixture_path = Path(__file__).parent / "fixtures" / name
    with fixture_path.open() as fh:
        return yaml.safe_load(fh)


def minimal_image(**overrides) -> dict:
    base = {
        "id": "dhi-test-image",
        "display_name": "Test Image",
        "source_tier": "primary",
        "criticality": "medium",
        "classification_status": "classified",
        "disposition": "mirror_only",
        "image_modification": {"strategy": "mirror_only"},
        "upstream": {"registry": "dhi.io", "name": "test", "tag": "1-debian13"},
        "ghcr": {"name": "dhi-test", "tag": "1-debian13"},
        "platform_compatibility": {
            "default": "linux/amd64",
            "supported": ["linux/amd64"],
        },
    }
    base.update(overrides)
    return base


def minimal_catalog(*images) -> dict:
    return {"apiVersion": "v1", "images": list(images)}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_valid_fixture_passes(self):
        catalog = load_fixture("valid_catalog.yaml")
        assert validate(catalog) == []

    def test_single_valid_image(self):
        catalog = minimal_catalog(minimal_image())
        assert validate(catalog) == []

    def test_two_valid_images_different_ids(self):
        img_a = minimal_image(id="dhi-a", ghcr={"name": "dhi-a", "tag": "1"})
        img_b = minimal_image(id="dhi-b", ghcr={"name": "dhi-b", "tag": "1"})
        assert validate(minimal_catalog(img_a, img_b)) == []


# ---------------------------------------------------------------------------
# Missing required top-level fields
# ---------------------------------------------------------------------------


class TestMissingTopLevel:
    def test_missing_api_version(self):
        catalog = {"images": [minimal_image()]}
        errors = validate(catalog)
        assert any("apiVersion" in e for e in errors)

    def test_missing_images_key(self):
        catalog = {"apiVersion": "v1"}
        errors = validate(catalog)
        assert any("images" in e for e in errors)

    def test_images_not_a_list(self):
        catalog = {"apiVersion": "v1", "images": "not-a-list"}
        errors = validate(catalog)
        assert any("list" in e for e in errors)


# ---------------------------------------------------------------------------
# Missing required image fields
# ---------------------------------------------------------------------------


class TestMissingImageFields:
    @pytest.mark.parametrize(
        "field",
        [
            "id",
            "display_name",
            "source_tier",
            "criticality",
            "classification_status",
            "disposition",
            "image_modification",
            "upstream",
            "ghcr",
            "platform_compatibility",
        ],
    )
    def test_missing_field(self, field: str):
        img = minimal_image()
        del img[field]
        errors = validate(minimal_catalog(img))
        assert any(field in e for e in errors), (
            f"Expected an error about missing field {field!r}, got: {errors}"
        )

    def test_missing_upstream_registry(self):
        img = minimal_image()
        del img["upstream"]["registry"]
        errors = validate(minimal_catalog(img))
        assert any("registry" in e for e in errors)

    def test_missing_upstream_tag(self):
        img = minimal_image()
        del img["upstream"]["tag"]
        errors = validate(minimal_catalog(img))
        assert any("tag" in e for e in errors)

    def test_missing_ghcr_name(self):
        img = minimal_image()
        del img["ghcr"]["name"]
        errors = validate(minimal_catalog(img))
        assert any("name" in e for e in errors)

    def test_missing_platform_supported(self):
        img = minimal_image()
        del img["platform_compatibility"]["supported"]
        errors = validate(minimal_catalog(img))
        assert any("supported" in e for e in errors)


# ---------------------------------------------------------------------------
# Invalid enum values
# ---------------------------------------------------------------------------


class TestInvalidEnums:
    def test_invalid_source_tier(self):
        img = minimal_image(source_tier="unknown-tier")
        errors = validate(minimal_catalog(img))
        assert any("source_tier" in e for e in errors)

    def test_invalid_criticality(self):
        img = minimal_image(criticality="super-critical")
        errors = validate(minimal_catalog(img))
        assert any("criticality" in e for e in errors)

    def test_invalid_classification_status(self):
        img = minimal_image(classification_status="approved")
        errors = validate(minimal_catalog(img))
        assert any("classification_status" in e for e in errors)

    def test_invalid_disposition(self):
        img = minimal_image(disposition="allow-anything")
        errors = validate(minimal_catalog(img))
        assert any("disposition" in e for e in errors)

    def test_invalid_strategy(self):
        img = minimal_image()
        img["image_modification"]["strategy"] = "bypass-all-checks"
        errors = validate(minimal_catalog(img))
        assert any("strategy" in e for e in errors)

    def test_platform_supported_empty_list(self):
        img = minimal_image()
        img["platform_compatibility"]["supported"] = []
        errors = validate(minimal_catalog(img))
        assert any("supported" in e for e in errors)


# ---------------------------------------------------------------------------
# Uniqueness constraints (bypass-attempt cases)
# ---------------------------------------------------------------------------


class TestUniquenessConstraints:
    def test_duplicate_ids_detected(self):
        img_a = minimal_image(id="dhi-same-id")
        img_b = minimal_image(id="dhi-same-id", ghcr={"name": "dhi-other", "tag": "1"})
        errors = validate(minimal_catalog(img_a, img_b))
        assert any("duplicate id" in e for e in errors)

    def test_duplicate_ghcr_refs_detected(self):
        img_a = minimal_image(id="dhi-a", ghcr={"name": "dhi-shared", "tag": "1"})
        img_b = minimal_image(id="dhi-b", ghcr={"name": "dhi-shared", "tag": "1"})
        errors = validate(minimal_catalog(img_a, img_b))
        assert any("duplicate GHCR ref" in e for e in errors)

    def test_bypass_attempt_invalid_strategy_value(self):
        """An attacker smuggling an unapproved strategy must be rejected."""
        img = minimal_image()
        img["image_modification"]["strategy"] = "no-verification-needed"
        errors = validate(minimal_catalog(img))
        assert errors, "Expected validation to fail on unapproved strategy"

    def test_bypass_attempt_image_modification_not_mapping(self):
        """image_modification set to a string instead of a mapping must fail."""
        img = minimal_image()
        img["image_modification"] = "mirror_only"
        errors = validate(minimal_catalog(img))
        assert any("mapping" in e for e in errors)

    def test_bypass_attempt_upstream_not_mapping(self):
        img = minimal_image()
        img["upstream"] = "dhi.io/test:1"
        errors = validate(minimal_catalog(img))
        assert any("mapping" in e for e in errors)


# ---------------------------------------------------------------------------
# Non-dict subfields not covered by bypass tests above
# ---------------------------------------------------------------------------


class TestValidateNonDictSubfields:
    def test_image_entry_not_a_mapping(self):
        """An image list element that is not a dict reports the index."""
        catalog = {"apiVersion": "v1", "images": ["not-a-dict"]}
        errors = validate(catalog)
        assert any("not a mapping" in e for e in errors)

    def test_ghcr_not_a_mapping(self):
        img = minimal_image()
        img["ghcr"] = "ghcr.io/foo/bar:1"
        errors = validate(minimal_catalog(img))
        assert any("ghcr must be a mapping" in e for e in errors)

    def test_platform_compatibility_not_a_mapping(self):
        img = minimal_image()
        img["platform_compatibility"] = "linux/amd64"
        errors = validate(minimal_catalog(img))
        assert any("platform_compatibility must be a mapping" in e for e in errors)


# ---------------------------------------------------------------------------
# main(): file I/O and exit-code contract
# ---------------------------------------------------------------------------


class TestMain:
    def test_missing_catalog_exits_2(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            validate_catalog_schema, "CATALOG_PATH", tmp_path / "nope.yaml"
        )
        with pytest.raises(SystemExit) as exc_info:
            validate_catalog_schema.main()
        assert exc_info.value.code == 2

    def test_invalid_yaml_exits_2(self, tmp_path, monkeypatch):
        p = tmp_path / "bad.yaml"
        p.write_text("key: [\n")  # unclosed flow sequence → ScannerError
        monkeypatch.setattr(validate_catalog_schema, "CATALOG_PATH", p)
        with pytest.raises(SystemExit) as exc_info:
            validate_catalog_schema.main()
        assert exc_info.value.code == 2

    def test_non_mapping_yaml_exits_2(self, tmp_path, monkeypatch):
        p = tmp_path / "list.yaml"
        p.write_text("- a\n- b\n")
        monkeypatch.setattr(validate_catalog_schema, "CATALOG_PATH", p)
        with pytest.raises(SystemExit) as exc_info:
            validate_catalog_schema.main()
        assert exc_info.value.code == 2

    def test_valid_catalog_prints_pass(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "valid.yaml"
        p.write_text("apiVersion: v1\nimages: []\n")
        monkeypatch.setattr(validate_catalog_schema, "CATALOG_PATH", p)
        validate_catalog_schema.main()  # must not raise
        assert "PASS" in capsys.readouterr().out

    def test_invalid_catalog_exits_1_with_fail(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "invalid.yaml"
        p.write_text("images: []\n")  # missing apiVersion
        monkeypatch.setattr(validate_catalog_schema, "CATALOG_PATH", p)
        with pytest.raises(SystemExit) as exc_info:
            validate_catalog_schema.main()
        assert exc_info.value.code == 1
        assert "FAIL" in capsys.readouterr().out
