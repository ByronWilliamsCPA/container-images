"""Tests for scripts/update_approved_lock.py.

Covers the upsert core that the A2 update-lock job force-pushes to main:
append vs in-place update (idempotency), null/missing/non-list ``promoted``,
non-dict YAML rejection, path-traversal containment, and metadata stamping.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import update_approved_lock as ual  # noqa: E402

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _write(path: Path, data: object) -> None:
    with path.open("w") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)


def _argv(lock: str = "lock.yaml", image_id: str = "dhi-postgres-16", **o) -> list[str]:
    return [
        "update_approved_lock.py",
        "--lock-file",
        lock,
        "--image-id",
        image_id,
        "--ghcr-ref",
        o.get("ghcr_ref", "ghcr.io/o/dhi-postgres:16"),
        "--source-digest",
        o.get("source_digest", DIGEST_A),
        "--target-digest",
        o.get("target_digest", DIGEST_A),
        "--promoted-at",
        o.get("promoted_at", "2026-06-28T00:00:00Z"),
        "--promoted-by",
        o.get("promoted_by", "https://example/run/1"),
    ]


@pytest.fixture
def lockfile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    _write(p, {"metadata": {"last_updated": "old"}, "promoted": []})
    return p


def _run(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", argv)
    return ual.main()


def test_append_new_entry(lockfile: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run(monkeypatch, _argv()) == 0
    data = yaml.safe_load(lockfile.read_text())
    assert len(data["promoted"]) == 1
    assert data["promoted"][0]["id"] == "dhi-postgres-16"
    assert data["promoted"][0]["target_digest"] == DIGEST_A


def test_idempotent_update_in_place(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(monkeypatch, _argv()) == 0
    # Re-promote the same id with a different digest: update, do not duplicate.
    assert _run(monkeypatch, _argv(target_digest=DIGEST_B)) == 0
    data = yaml.safe_load(lockfile.read_text())
    assert len(data["promoted"]) == 1
    assert data["promoted"][0]["target_digest"] == DIGEST_B


def test_distinct_ids_both_appended(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(monkeypatch, _argv(image_id="dhi-postgres-16")) == 0
    assert _run(monkeypatch, _argv(image_id="dhi-redis-7")) == 0
    data = yaml.safe_load(lockfile.read_text())
    assert {e["id"] for e in data["promoted"]} == {"dhi-postgres-16", "dhi-redis-7"}


def test_missing_promoted_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    _write(p, {"metadata": {}})  # no 'promoted' key at all
    assert _run(monkeypatch, _argv()) == 0
    assert len(yaml.safe_load(p.read_text())["promoted"]) == 1


def test_null_promoted_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    p.write_text("metadata: {}\npromoted:\n")  # promoted: null
    assert _run(monkeypatch, _argv()) == 0
    assert len(yaml.safe_load(p.read_text())["promoted"]) == 1


def test_non_dict_yaml_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    p.write_text("- a\n- b\n")  # a list, not a mapping
    assert _run(monkeypatch, _argv()) == 1


def test_non_list_promoted_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    _write(p, {"promoted": {"not": "a list"}})
    assert _run(monkeypatch, _argv()) == 1


def test_path_traversal_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        _run(monkeypatch, _argv(lock="../escape.yaml"))


def test_missing_lock_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert _run(monkeypatch, _argv(lock="nope.yaml")) == 1


def test_metadata_last_updated_stamped(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(monkeypatch, _argv(promoted_at="2026-07-01T12:00:00Z")) == 0
    data = yaml.safe_load(lockfile.read_text())
    assert data["metadata"]["last_updated"] == "2026-07-01T12:00:00Z"


def test_no_temp_file_left_behind(
    lockfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run(monkeypatch, _argv()) == 0
    assert not (lockfile.parent / "lock.yaml.tmp").exists()


def test_invalid_yaml_syntax_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "lock.yaml"
    p.write_text("key: [unclosed\n")  # flow sequence never closed → ScannerError
    assert _run(monkeypatch, _argv()) == 1
