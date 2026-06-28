"""Tests for scripts/load_scanner_policy.py.

Covers the policy-to-knob translation the A2 workflow relies on: the Snyk
severity floor, the Trivy severity list, fail-safe exception expiry, and the
end-to-end emission of GITHUB_OUTPUT keys plus a generated .trivyignore.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import load_scanner_policy as lsp  # noqa: E402

TODAY = date(2026, 6, 28)


def _default_policy() -> dict:
    return {
        "scanner_policy": {
            "snyk": {
                "critical": "block",
                "high": "block",
                "medium": "warn",
                "low": "record",
            },
            "trivy": {
                "critical": "block",
                "high": "block",
                "medium": "record",
                "low": "ignore",
            },
            "upstream_cosign": {
                "required": False,
                "advisory": True,
                "expected_identity_regexp": ".*",
                "expected_issuer_regexp": ".*",
            },
        },
        "exceptions": [],
    }


def test_snyk_threshold_lowest_blocking() -> None:
    assert lsp._snyk_threshold({"critical": "block", "high": "block"}) == "high"
    assert (
        lsp._snyk_threshold({"critical": "block", "high": "block", "medium": "block"})
        == "medium"
    )


def test_snyk_threshold_none_blocking_defaults_critical() -> None:
    assert lsp._snyk_threshold({"high": "warn", "low": "record"}) == "critical"


def test_trivy_severities_highest_first() -> None:
    assert (
        lsp._trivy_severities({"critical": "block", "high": "block"}) == "CRITICAL,HIGH"
    )
    assert (
        lsp._trivy_severities({"critical": "block", "high": "block", "medium": "block"})
        == "CRITICAL,HIGH,MEDIUM"
    )


def test_parse_expiry() -> None:
    assert lsp._parse_expiry("2026-12-31") == date(2026, 12, 31)
    assert lsp._parse_expiry("not-a-date") is None
    assert lsp._parse_expiry(None) is None
    assert lsp._parse_expiry(date(2026, 1, 1)) == date(2026, 1, 1)


def test_active_exceptions_filters_by_image_and_scanner() -> None:
    exceptions = [
        {
            "image_id": "img",
            "cve_id": "CVE-1",
            "scanner": "trivy",
            "expires": "2026-12-31",
        },
        {
            "image_id": "img",
            "cve_id": "CVE-2",
            "scanner": "snyk",
            "expires": "2026-12-31",
        },
        {
            "image_id": "img",
            "cve_id": "CVE-3",
            "scanner": "both",
            "expires": "2026-12-31",
        },
        {
            "image_id": "other",
            "cve_id": "CVE-4",
            "scanner": "trivy",
            "expires": "2026-12-31",
        },
    ]
    trivy, snyk, skipped = lsp._active_exceptions(exceptions, "img", TODAY)
    assert trivy == ["CVE-1", "CVE-3"]
    assert snyk == ["CVE-2", "CVE-3"]
    assert skipped == []


def test_active_exceptions_expired_is_failsafe() -> None:
    exceptions = [
        {
            "image_id": "img",
            "cve_id": "CVE-OLD",
            "scanner": "trivy",
            "expires": "2020-01-01",
        },
        {
            "image_id": "img",
            "cve_id": "CVE-BAD",
            "scanner": "trivy",
            "expires": "not-a-date",
        },
    ]
    trivy, snyk, skipped = lsp._active_exceptions(exceptions, "img", TODAY)
    assert trivy == []
    assert snyk == []
    assert len(skipped) == 2  # both dropped, still blocking


def _run_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy: dict,
    image_id: str = "dhi-postgres-16",
) -> tuple[int, dict[str, str], Path]:
    policy_path = tmp_path / "policies.yaml"
    with policy_path.open("w") as fh:
        yaml.safe_dump(policy, fh, sort_keys=False)
    out_path = tmp_path / "gh_output"
    out_path.write_text("")
    trivyignore = tmp_path / ".trivyignore"
    argv = [
        "load_scanner_policy.py",
        "--policy-file",
        str(policy_path),
        "--image-id",
        image_id,
        "--trivyignore-out",
        str(trivyignore),
        "--github-output",
        str(out_path),
        "--today",
        "2026-06-28",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    rc = lsp.main()
    outputs: dict[str, str] = {}
    for line in out_path.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return rc, outputs, trivyignore


def test_main_emits_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, outputs, trivyignore = _run_main(tmp_path, monkeypatch, _default_policy())
    assert rc == 0
    assert outputs["snyk_threshold"] == "high"
    assert outputs["trivy_severities"] == "CRITICAL,HIGH"
    assert outputs["cosign_required"] == "false"
    assert outputs["cosign_identity_pinned"] == "false"
    assert outputs["trivy_exception_count"] == "0"
    assert trivyignore.exists()


def test_main_pinned_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _default_policy()
    policy["scanner_policy"]["upstream_cosign"]["expected_identity_regexp"] = (
        "https://github.com/acme/.+"
    )
    policy["scanner_policy"]["upstream_cosign"]["required"] = True
    rc, outputs, _ = _run_main(tmp_path, monkeypatch, policy)
    assert rc == 0
    assert outputs["cosign_identity_pinned"] == "true"
    assert outputs["cosign_required"] == "true"


def test_main_writes_trivyignore_from_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _default_policy()
    policy["exceptions"] = [
        {
            "image_id": "dhi-postgres-16",
            "cve_id": "CVE-2026-1",
            "scanner": "trivy",
            "expires": "2026-12-31",
        },
    ]
    rc, outputs, trivyignore = _run_main(tmp_path, monkeypatch, policy)
    assert rc == 0
    assert outputs["trivy_exception_count"] == "1"
    assert "CVE-2026-1" in trivyignore.read_text()


def test_main_rejects_non_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "policies.yaml"
    policy_path.write_text("- not\n- a mapping\n")
    out_path = tmp_path / "gh_output"
    argv = [
        "load_scanner_policy.py",
        "--policy-file",
        str(policy_path),
        "--image-id",
        "x",
        "--trivyignore-out",
        str(tmp_path / ".trivyignore"),
        "--github-output",
        str(out_path),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert lsp.main() == 1


def test_main_missing_scanner_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, _, _ = _run_main(tmp_path, monkeypatch, {"exceptions": []})
    assert rc == 1


def test_main_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = [
        "load_scanner_policy.py",
        "--policy-file",
        str(tmp_path / "nope.yaml"),
        "--image-id",
        "x",
        "--trivyignore-out",
        str(tmp_path / ".trivyignore"),
        "--github-output",
        str(tmp_path / "out"),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert lsp.main() == 1
