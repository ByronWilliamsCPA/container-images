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


def vendor_upstream(**overrides) -> dict:
    """A valid Docker Hub vendor upstream block (immutable tag plus digest)."""
    base = {
        "registry": "docker.io",
        "name": "supabase/gotrue",
        "tag": "v2.197.0",
        "digest": "sha256:" + "b" * 64,
    }
    base.update(overrides)
    return base


def vendor_image(**overrides) -> dict:
    """A valid vendor-tier catalog entry."""
    base = minimal_image(
        id="vendor-supabase-gotrue",
        source_tier="vendor",
        upstream=vendor_upstream(),
        ghcr={"name": "vendor-supabase-gotrue", "tag": "v2.197.0"},
    )
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
# Value validation: registry allowlist, name/tag shapes, digest pin
# (RT-2 / RT-6 / RT-7 bypass attempts)
# ---------------------------------------------------------------------------


class TestRegistryAllowlist:
    def test_unapproved_registry_rejected(self):
        """An attacker-controlled registry must not pass presence-only checks."""
        img = minimal_image()
        img["upstream"]["registry"] = "evil.example.com"
        errors = validate(minimal_catalog(img))
        assert any("registry" in e and "not allowed" in e for e in errors)

    def test_lookalike_registry_rejected(self):
        img = minimal_image()
        img["upstream"]["registry"] = "dhi.io.evil.com"
        errors = validate(minimal_catalog(img))
        assert any("not allowed" in e for e in errors)

    def test_allowed_registries_pass(self):
        """Each tier is accepted with the one registry it owns."""
        for tier, upstream in (
            ("primary", {"registry": "dhi.io", "name": "postgres", "tag": "1-d13"}),
            (
                "distroless",
                {"registry": "gcr.io", "name": "distroless/static", "tag": "1-d13"},
            ),
            ("vendor", vendor_upstream()),
        ):
            img = minimal_image(source_tier=tier, upstream=upstream)
            assert validate(minimal_catalog(img)) == [], f"{tier} should be allowed"

    @pytest.mark.parametrize(
        ("tier", "registry", "name"),
        [
            ("primary", "docker.io", "supabase/gotrue"),
            ("primary", "gcr.io", "distroless/static"),
            ("distroless", "dhi.io", "postgres"),
            ("distroless", "docker.io", "supabase/gotrue"),
            ("vendor", "dhi.io", "postgres"),
            ("vendor", "gcr.io", "distroless/static"),
        ],
    )
    def test_tier_cannot_use_another_tiers_registry(self, tier, registry, name):
        """The allowlist is per tier, not one global set."""
        upstream = vendor_upstream(registry=registry, name=name)
        if tier != "vendor":
            upstream.pop("digest")
            upstream["tag"] = "1-debian13"
        img = minimal_image(source_tier=tier, upstream=upstream)
        errors = validate(minimal_catalog(img))
        assert any(
            "not allowed for source_tier" in e and repr(tier) in e for e in errors
        ), errors

    def test_vendor_with_dhi_registry_rejected(self):
        img = minimal_image(
            source_tier="vendor", upstream=vendor_upstream(registry="dhi.io")
        )
        errors = validate(minimal_catalog(img))
        assert any("registry" in e and "not allowed" in e for e in errors)

    def test_primary_with_docker_hub_rejected(self):
        img = minimal_image(
            upstream={
                "registry": "docker.io",
                "name": "supabase/gotrue",
                "tag": "v2.197.0",
            }
        )
        errors = validate(minimal_catalog(img))
        assert any("registry" in e and "not allowed" in e for e in errors)

    def test_unknown_tier_reports_only_the_enum_error(self):
        """A bad source_tier must not also raise a misleading registry error."""
        img = minimal_image(source_tier="bogus")
        errors = validate(minimal_catalog(img))
        assert len(errors) == 1
        assert "source_tier" in errors[0]

    def test_non_string_tier_does_not_crash(self):
        img = minimal_image(source_tier=["vendor"])
        errors = validate(minimal_catalog(img))
        assert any("source_tier" in e for e in errors)


class TestUpstreamNameShape:
    def test_path_traversal_name_rejected(self):
        img = minimal_image()
        img["upstream"]["name"] = "../../etc/passwd"
        errors = validate(minimal_catalog(img))
        assert any("upstream.name" in e for e in errors)

    def test_uppercase_name_rejected(self):
        img = minimal_image()
        img["upstream"]["name"] = "Library/Postgres"
        errors = validate(minimal_catalog(img))
        assert any("upstream.name" in e for e in errors)

    def test_non_string_name_rejected_without_crash(self):
        img = minimal_image()
        img["upstream"]["name"] = ["not", "a", "string"]
        errors = validate(minimal_catalog(img))
        assert any("upstream.name" in e for e in errors)

    def test_nested_path_name_allowed(self):
        img = minimal_image(source_tier="distroless")
        img["upstream"]["registry"] = "gcr.io"
        img["upstream"]["name"] = "distroless/python3-debian12"
        # tag stays non-mutable so the digest rule does not also fire
        assert validate(minimal_catalog(img)) == []

    def test_docker_hub_namespace_repo_name_allowed(self):
        """Docker Hub names are <namespace>/<repo> (single slash)."""
        img = vendor_image()
        assert img["upstream"]["name"] == "supabase/gotrue"
        assert validate(minimal_catalog(img)) == []

    @pytest.mark.parametrize(
        "name",
        ["gotrue", "supabase/gotrue/extra", "Supabase/gotrue", "../supabase"],
        ids=["bare", "three_segments", "uppercase", "traversal"],
    )
    def test_docker_hub_name_shape_enforced(self, name):
        img = vendor_image()
        img["upstream"]["name"] = name
        errors = validate(minimal_catalog(img))
        assert any("upstream.name" in e for e in errors)


class TestGhcrNameShape:
    def test_ghcr_name_traversal_rejected(self):
        img = minimal_image()
        img["ghcr"]["name"] = "../../org-secret"
        errors = validate(minimal_catalog(img))
        assert any("ghcr.name" in e for e in errors)

    def test_ghcr_name_extra_segment_rejected(self):
        """A second path segment could push outside the org namespace."""
        img = minimal_image()
        img["ghcr"]["name"] = "dhi-test/evil"
        errors = validate(minimal_catalog(img))
        assert any("ghcr.name" in e for e in errors)

    def test_ghcr_name_uppercase_rejected(self):
        img = minimal_image()
        img["ghcr"]["name"] = "DHI-Test"
        errors = validate(minimal_catalog(img))
        assert any("ghcr.name" in e for e in errors)


class TestTagShape:
    def test_tag_with_space_rejected(self):
        img = minimal_image()
        img["upstream"]["tag"] = "1-debian13 && rm -rf /"
        errors = validate(minimal_catalog(img))
        assert any("upstream.tag" in e for e in errors)

    def test_ghcr_tag_with_slash_rejected(self):
        img = minimal_image()
        img["ghcr"]["tag"] = "1/../latest"
        errors = validate(minimal_catalog(img))
        assert any("ghcr.tag" in e for e in errors)


class TestMutableTagDigestPin:
    def test_latest_without_digest_rejected(self):
        """RT-6: a mutable tag must be backed by a pinned digest."""
        img = minimal_image(
            source_tier="distroless",
            upstream={
                "registry": "gcr.io",
                "name": "distroless/static",
                "tag": "latest",
            },
        )
        errors = validate(minimal_catalog(img))
        assert any("mutable" in e and "digest" in e for e in errors)

    def test_latest_with_valid_digest_passes(self):
        digest = "sha256:" + "a" * 64
        img = minimal_image(
            source_tier="distroless",
            upstream={
                "registry": "gcr.io",
                "name": "distroless/static",
                "tag": "latest",
                "digest": digest,
            },
        )
        assert validate(minimal_catalog(img)) == []

    def test_malformed_digest_rejected(self):
        img = minimal_image(
            upstream={
                "registry": "dhi.io",
                "name": "postgres",
                "tag": "16-debian13",
                "digest": "sha256:not-hex",
            }
        )
        errors = validate(minimal_catalog(img))
        assert any("digest" in e for e in errors)

    def test_immutable_tag_needs_no_digest(self):
        img = minimal_image(
            upstream={"registry": "dhi.io", "name": "postgres", "tag": "16-debian13"}
        )
        assert validate(minimal_catalog(img)) == []


# ---------------------------------------------------------------------------
# Vendor tier: third-party application images mirrored from Docker Hub
# (ADR-032). The digest is mandatory and floating tags are refused.
# ---------------------------------------------------------------------------


class TestVendorTier:
    def test_vendor_entry_accepted(self):
        assert validate(minimal_catalog(vendor_image())) == []

    def test_vendor_without_digest_rejected(self):
        img = vendor_image()
        del img["upstream"]["digest"]
        errors = validate(minimal_catalog(img))
        assert any("upstream.digest is required" in e for e in errors)

    def test_vendor_with_immutable_tag_still_needs_digest(self):
        """Unlike primary, a pinned-looking version tag does not excuse the digest."""
        img = vendor_image()
        img["upstream"]["tag"] = "v2.197.0"
        del img["upstream"]["digest"]
        assert validate(minimal_catalog(img))

    def test_primary_with_immutable_tag_needs_no_digest(self):
        """The digest requirement is vendor-specific; primary behaviour is unchanged."""
        assert validate(minimal_catalog(minimal_image())) == []

    def test_vendor_with_latest_rejected_without_digest(self):
        img = vendor_image()
        img["upstream"]["tag"] = "latest"
        del img["upstream"]["digest"]
        errors = validate(minimal_catalog(img))
        assert any("mutable" in e and "'latest'" in e for e in errors)
        assert any("upstream.digest is required" in e for e in errors)

    def test_vendor_with_latest_rejected_even_with_digest(self):
        """A digest does not legitimise a floating tag for vendor images."""
        img = vendor_image()
        img["upstream"]["tag"] = "latest"
        errors = validate(minimal_catalog(img))
        assert any("mutable" in e and "not allowed" in e for e in errors)

    @pytest.mark.parametrize("tag", ["stable", "edge", "main", "nightly", "LATEST"])
    def test_vendor_mutable_tags_rejected(self, tag):
        img = vendor_image()
        img["upstream"]["tag"] = tag
        errors = validate(minimal_catalog(img))
        assert any("mutable" in e for e in errors)

    def test_vendor_with_malformed_digest_rejected(self):
        img = vendor_image()
        img["upstream"]["digest"] = "sha256:not-hex"
        errors = validate(minimal_catalog(img))
        assert any("upstream.digest" in e and "sha256" in e for e in errors)

    def test_vendor_with_non_string_digest_rejected_without_crash(self):
        img = vendor_image()
        img["upstream"]["digest"] = 12345
        errors = validate(minimal_catalog(img))
        assert any("upstream.digest" in e for e in errors)

    def test_vendor_ghcr_name_stays_single_segment(self):
        img = vendor_image()
        img["ghcr"]["name"] = "supabase/gotrue"
        errors = validate(minimal_catalog(img))
        assert any("ghcr.name" in e for e in errors)


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
