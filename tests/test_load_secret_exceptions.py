"""Tests for the path-scoped secret exceptions in scripts/load_scanner_policy.py.

Secret findings are not CVEs: the plain .trivyignore cannot scope one to a path,
and Trivy exits non-zero on a HIGH secret regardless of --ignore-unfixed. These
tests pin the behaviour the vendor mirror job relies on: strict validation, the
same fail-safe expiry as CVE exceptions, and a YAML ignore file as the gate input.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

_SCRIPT = Path(__file__).parent.parent / "scripts" / "load_scanner_policy.py"
_SPEC = importlib.util.spec_from_file_location("load_scanner_policy", _SCRIPT)
assert _SPEC is not None
assert _SPEC.loader is not None
lsp = importlib.util.module_from_spec(_SPEC)
sys.modules["load_scanner_policy"] = lsp
_SPEC.loader.exec_module(lsp)

TODAY = date(2026, 10, 19)
KEY_PATH = "/app/lib/gen_rpc-3.6.1/priv/ssl/ca.key.pem"
TICKET = "https://github.com/ByronWilliamsCPA/container-images/issues/59"


def _entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "image_id": "img",
        "rule_id": "private-key",
        "path": KEY_PATH,
        "expires": "2026-11-17",
        "ticket": TICKET,
        "justification": "test key shipped by a dependency",
    }
    entry.update(overrides)
    return entry


def test_active_secret_exception_is_kept() -> None:
    record, skip = lsp._secret_exception(_entry(), "img", TODAY)
    assert skip is None
    assert record == ("private-key", KEY_PATH, date(2026, 11, 17), TICKET)


def test_other_images_are_ignored_silently() -> None:
    assert lsp._secret_exception(_entry(), "other", TODAY) == (None, None)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"expires": "2026-10-18"}, "expired"),
        ({"expires": "soon"}, "invalid expires"),
        ({"expires": None}, "invalid expires"),
        ({"rule_id": "Private Key"}, "malformed rule_id"),
        ({"rule_id": ""}, "malformed rule_id"),
        ({"path": "app/lib/ca.key.pem"}, "exact absolute path"),
        ({"path": "/app/lib/*.pem"}, "exact absolute path"),
        ({"path": "/app/lib/{a,b}.pem"}, "exact absolute path"),
        ({"path": "/app/../etc/ssl/private/x.key"}, "exact absolute path"),
        ({"path": "/app/with space/x.key"}, "exact absolute path"),
        ({"path": ""}, "exact absolute path"),
    ],
)
def test_invalid_secret_exceptions_are_dropped_fail_safe(
    overrides: dict[str, object], reason: str
) -> None:
    record, skip = lsp._secret_exception(_entry(**overrides), "img", TODAY)
    assert record is None
    assert skip is not None
    assert reason in skip


def test_active_secret_exceptions_splits_kept_and_dropped() -> None:
    active, skipped = lsp._active_secret_exceptions(
        [_entry(), _entry(expires="2020-01-01"), _entry(image_id="x")], "img", TODAY
    )
    assert len(active) == 1
    assert len(skipped) == 1


def test_yaml_ignore_file_carries_cves_and_exact_paths() -> None:
    text = lsp._render_trivyignore_yaml(
        ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"],
        [("private-key", KEY_PATH, date(2026, 11, 17), TICKET)],
        "img",
    )
    doc = yaml.safe_load(text)
    assert [v["id"] for v in doc["vulnerabilities"]] == [
        "CVE-2026-1",
        "GHSA-aaaa-bbbb-cccc",
    ]
    assert doc["secrets"] == [
        {
            "id": "private-key",
            "paths": [KEY_PATH],
            "statement": TICKET,
            # expires 2026-11-17 is inclusive; Trivy's expired_at is exclusive.
            "expired_at": date(2026, 11, 18),
        }
    ]
    assert "img" in text.splitlines()[1]


def test_secret_exception_is_active_on_its_last_day_and_dropped_after() -> None:
    entry = {
        "image_id": "img",
        "rule_id": "private-key",
        "path": KEY_PATH,
        "expires": "2026-11-17",
        "ticket": TICKET,
    }
    last_day, _ = lsp._secret_exception(entry, "img", date(2026, 11, 17))
    next_day, skip = lsp._secret_exception(entry, "img", date(2026, 11, 18))
    assert last_day is not None
    assert next_day is None
    assert skip is not None
    assert "expired" in skip
    # The rendered Trivy expiry must start AFTER the last active day.
    doc = yaml.safe_load(lsp._render_trivyignore_yaml([], [last_day], "img"))
    assert doc["secrets"][0]["expired_at"] > date(2026, 11, 17)


def test_yaml_ignore_file_with_no_exceptions_is_still_valid() -> None:
    doc = yaml.safe_load(lsp._render_trivyignore_yaml([], [], "img"))
    assert doc == {"vulnerabilities": [], "secrets": []}


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy: dict[str, object],
    *,
    yaml_out: bool,
) -> tuple[int, dict[str, str], Path, Path]:
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False))
    gh_out = tmp_path / "gh_output"
    gh_out.write_text("")
    plain = tmp_path / ".trivyignore"
    gate = tmp_path / ".trivyignore.yaml"
    argv = [
        "load_scanner_policy.py",
        "--policy-file",
        str(policy_path),
        "--image-id",
        "img",
        "--trivyignore-out",
        str(plain),
        "--github-output",
        str(gh_out),
        "--today",
        "2026-10-19",
    ]
    if yaml_out:
        argv += ["--trivyignore-yaml-out", str(gate)]
    monkeypatch.setattr(sys, "argv", argv)
    rc = lsp.main()
    outputs = dict(
        line.partition("=")[::2]
        for line in gh_out.read_text().splitlines()
        if "=" in line
    )
    return rc, outputs, plain, gate


def _policy() -> dict[str, object]:
    return {
        "scanner_policy": {"trivy": {"critical": "block", "high": "block"}},
        "exceptions": [
            {
                "image_id": "img",
                "cve_id": "CVE-2026-1",
                "scanner": "trivy",
                "expires": "2026-11-17",
            }
        ],
        "secret_exceptions": [_entry()],
    }


def test_main_points_the_gate_at_the_yaml_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, outputs, _, gate = _run(tmp_path, monkeypatch, _policy(), yaml_out=True)
    assert rc == 0
    assert outputs["trivyignore_file"] == str(gate)
    assert outputs["trivy_exception_count"] == "1"
    assert outputs["trivy_secret_exception_count"] == "1"
    doc = yaml.safe_load(gate.read_text())
    assert doc["secrets"][0]["paths"] == [KEY_PATH]


def test_main_without_yaml_out_does_not_apply_secret_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, outputs, plain, _ = _run(tmp_path, monkeypatch, _policy(), yaml_out=False)
    assert rc == 0
    assert outputs["trivyignore_file"] == str(plain)
    assert outputs["trivy_secret_exception_count"] == "0"
    assert "no YAML ignore output requested" in capsys.readouterr().out


def test_main_rejects_a_non_list_secret_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy()
    policy["secret_exceptions"] = {"not": "a list"}
    rc, _, _, _ = _run(tmp_path, monkeypatch, policy, yaml_out=True)
    assert rc == 1
