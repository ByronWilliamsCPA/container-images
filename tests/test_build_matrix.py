"""Tests for scripts/build_matrix.py.

Covers: GITHUB_OUTPUT path validation (the security-relevant guard that the
.snyk path-traversal suppression relies on) and matrix include construction.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import build_matrix  # noqa: E402
from build_matrix import build_include, resolve_output_path  # noqa: E402

# ---------------------------------------------------------------------------
# resolve_output_path: the four branches the .snyk suppression depends on
# ---------------------------------------------------------------------------


class TestResolveOutputPath:
    def test_empty_string_falls_back_to_stdout(self):
        """An unset GITHUB_OUTPUT (empty string) yields None -> stdout."""
        assert resolve_output_path("") is None

    def test_relative_path_rejected(self):
        """A non-absolute path is rejected rather than written to."""
        assert resolve_output_path("relative/output.txt") is None

    def test_absolute_path_with_missing_parent_rejected(self, tmp_path: Path):
        """An absolute path whose parent directory does not exist is rejected."""
        missing = tmp_path / "does-not-exist" / "output.txt"
        assert resolve_output_path(str(missing)) is None

    def test_valid_absolute_path_accepted(self, tmp_path: Path):
        """An absolute path with an existing parent is returned unchanged."""
        valid = tmp_path / "github_output.txt"
        result = resolve_output_path(str(valid))
        assert result == valid

    def test_parent_must_be_a_directory_not_a_file(self, tmp_path: Path):
        """A path whose parent is a regular file (not a dir) is rejected."""
        parent_file = tmp_path / "not-a-dir"
        parent_file.write_text("x", encoding="utf-8")
        candidate = parent_file / "output.txt"
        assert resolve_output_path(str(candidate)) is None

    def test_set_but_invalid_warns_on_stderr(self, capsys):
        """A set-but-invalid value warns so a CI misconfiguration is visible."""
        resolve_output_path("relative/output.txt")
        assert "GITHUB_OUTPUT" in capsys.readouterr().err

    def test_unset_value_is_silent(self, capsys):
        """An unset value is the expected local-run case and must not warn."""
        resolve_output_path("")
        assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# build_include: matrix row construction and its documented defaults
# ---------------------------------------------------------------------------


def _full_image() -> dict:
    return {
        "id": "dhi-test",
        "criticality": "high",
        "upstream": {"registry": "dhi.io", "name": "test", "tag": "1-debian13"},
        "ghcr": {"name": "dhi-test", "tag": "1-debian13"},
        "platform_compatibility": {
            "default": "linux/arm64",
            "supported": ["linux/arm64"],
        },
    }


class TestBuildInclude:
    def test_maps_all_fields(self):
        row = build_include(_full_image())
        assert row == {
            "id": "dhi-test",
            "upstream_registry": "dhi.io",
            "upstream_name": "test",
            "upstream_tag": "1-debian13",
            "ghcr_name": "dhi-test",
            "ghcr_tag": "1-debian13",
            "platform": "linux/arm64",
            "criticality": "high",
        }

    def test_platform_and_criticality_defaults(self):
        """A row missing platform_compatibility/criticality uses documented defaults."""
        img = _full_image()
        del img["platform_compatibility"]
        del img["criticality"]
        row = build_include(img)
        assert row["platform"] == "linux/amd64"
        assert row["criticality"] == "low"

    def test_missing_required_field_exits_with_message(self, capsys):
        """A catalog entry with a missing required field exits 1 with a clear message.

        validate_catalog_schema.py guards this in CI, but standalone invocations
        of build_matrix.py should get a diagnostic rather than a bare KeyError.
        """
        img = _full_image()
        del img["upstream"]["registry"]  # simulate a structurally incomplete entry
        with pytest.raises(SystemExit) as exc_info:
            build_include(img)
        assert exc_info.value.code == 1
        stderr = capsys.readouterr().err
        assert "dhi-test" in stderr
        assert "validate_catalog_schema.py" in stderr


# ---------------------------------------------------------------------------
# main(): file I/O, stdout fallback, and GITHUB_OUTPUT write
# ---------------------------------------------------------------------------


class TestMain:
    def test_missing_catalog_exits_1(self, tmp_path, monkeypatch):
        monkeypatch.setattr(build_matrix, "CATALOG_PATH", tmp_path / "nope.yaml")
        with pytest.raises(SystemExit) as exc_info:
            build_matrix.main()
        assert exc_info.value.code == 1

    def test_empty_catalog_writes_to_stdout(self, tmp_path, monkeypatch, capsys):
        p = tmp_path / "images.yaml"
        p.write_text("images: []\n")
        monkeypatch.setattr(build_matrix, "CATALOG_PATH", p)
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        build_matrix.main()
        out = capsys.readouterr().out
        assert "dhi_matrix=" in out
        assert "distroless_matrix=" in out
        assert "dhi_count=0" in out
        assert "distroless_count=0" in out

    def test_writes_to_github_output_file(self, tmp_path, monkeypatch):
        p = tmp_path / "images.yaml"
        p.write_text("images: []\n")
        monkeypatch.setattr(build_matrix, "CATALOG_PATH", p)
        out_file = tmp_path / "gh_output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
        build_matrix.main()
        content = out_file.read_text()
        assert "dhi_matrix=" in content
        assert "distroless_matrix=" in content

    def test_splits_primary_and_distroless(self, tmp_path, monkeypatch, capsys):
        catalog_yaml = textwrap.dedent("""\
            images:
              - id: dhi-alpha
                source_tier: primary
                criticality: high
                upstream: {registry: dhi.io, name: alpha, tag: "1"}
                ghcr: {name: dhi-alpha, tag: "1"}
                platform_compatibility: {default: linux/amd64, supported: [linux/amd64]}
              - id: dl-base
                source_tier: distroless
                criticality: low
                upstream: {registry: gcr.io, name: distroless/base, tag: latest}
                ghcr: {name: dl-base, tag: latest}
                platform_compatibility: {default: linux/amd64, supported: [linux/amd64]}
        """)
        p = tmp_path / "images.yaml"
        p.write_text(catalog_yaml)
        monkeypatch.setattr(build_matrix, "CATALOG_PATH", p)
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        build_matrix.main()
        out = capsys.readouterr().out
        parsed = {
            k: v
            for line in out.splitlines()
            if "=" in line
            for k, v in [line.split("=", 1)]
        }
        assert json.loads(parsed["dhi_matrix"])["include"][0]["id"] == "dhi-alpha"
        assert json.loads(parsed["distroless_matrix"])["include"][0]["id"] == "dl-base"
        assert parsed["dhi_count"] == "1"
        assert parsed["distroless_count"] == "1"
