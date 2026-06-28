#!/usr/bin/env python3
"""Translate catalog/policies.yaml into concrete scanner settings.

Consumed by the promote job in publish-approved-image.yml (A2). The workflow
keeps catalog/policies.yaml as the single source of truth for scanner
thresholds and CVE exceptions; this script reads that declarative policy and
emits the concrete knobs each scanner consumes:

  * Snyk:  a single ``--severity-threshold`` floor (the lowest blocking
    severity).
  * Trivy: a comma-separated ``severity`` list of blocking severities, plus a
    generated ``.trivyignore`` of non-expired CVE exceptions for the image.
  * Cosign: the ``required`` flag and the certificate identity / issuer
    regexps used to verify the upstream signature.

Outputs are written as ``key=value`` lines to the file named by
``--github-output`` (default: the ``GITHUB_OUTPUT`` environment variable) so a
later workflow step can reference them via ``steps.<id>.outputs.<key>``.

Expiry handling is fail-safe: an exception whose ``expires`` date is in the
past, missing, or unparseable does NOT suppress its finding, so the scanner
gate still blocks. A sloppy policy file therefore fails closed, never open.

Exit codes:
  0  Policy loaded and outputs written.
  1  Argument error, missing/invalid policy file, or malformed policy.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

# Severity ranking, lowest to highest. Used to pick the Snyk threshold floor
# and to order the Trivy severity list deterministically.
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]
_BLOCK = "block"
_VALID_SCANNERS = {"snyk", "trivy", "both"}

# Strict allowlists for the two policy-derived values that get written to disk.
# Both reject path separators, dot-dot, whitespace, and newlines, so nothing
# from the policy file can smuggle traversal or injection into .trivyignore.
# CVE-2021-44228 and GHSA-jfh8-c2jp-5v3q both match _CVE_RE.
_CVE_RE = re.compile(r"^[A-Za-z0-9-]+$")
_IMAGE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class _PolicyError(Exception):
    """Raised when the policy file is missing, unreadable, or malformed."""


def _fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def _allowed_roots() -> list[Path]:
    """Directories the script may read from or write to.

    The repository checkout (``cwd``) plus the CI runner temp and the system
    temp dir, which is where ``$GITHUB_OUTPUT`` and test fixtures legitimately
    live. Anything resolving outside all of these is treated as a traversal.
    """
    roots = [Path.cwd()]
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        roots.append(Path(runner_temp))
    roots.append(Path(tempfile.gettempdir()))
    return roots


def _resolve_within(raw: str, allowed: list[Path]) -> Path:
    """Resolve ``raw`` and confirm it stays inside one of ``allowed``.

    The path arrives as a CLI argument (or ``$GITHUB_OUTPUT``) and is therefore
    untrusted. A traversal value (e.g. ``../../etc/passwd``) would otherwise let
    a faulty or hostile invocation read or overwrite files outside the sanctioned
    roots. Resolving and asserting containment closes that path-injection vector.

    Raises:
        SystemExit: If the resolved path escapes every allowed root.
    """
    candidate = Path(raw).resolve()
    for base in allowed:
        resolved_base = base.resolve()
        if candidate == resolved_base or resolved_base in candidate.parents:
            return candidate
    print(f"ERROR: path escapes allowed roots: {raw}", file=sys.stderr)
    raise SystemExit(1)


def _blocking_severities(scanner_cfg: dict[str, str]) -> list[str]:
    """Return severities whose action is ``block``, lowest-first."""
    return [
        sev
        for sev in _SEVERITY_ORDER
        if str(scanner_cfg.get(sev, "")).lower() == _BLOCK
    ]


def _snyk_threshold(snyk_cfg: dict[str, str]) -> str:
    """Lowest blocking severity is the Snyk ``--severity-threshold`` floor.

    Snyk fails the scan on any finding at or above the floor, so the floor is
    the least-severe level the policy marks ``block``. If nothing blocks, fall
    back to ``critical`` (the most permissive floor that still scans).
    """
    blocking = _blocking_severities(snyk_cfg)
    return blocking[0] if blocking else "critical"


def _trivy_severities(trivy_cfg: dict[str, str]) -> str:
    """Comma-separated uppercase list of blocking severities, highest-first."""
    blocking = _blocking_severities(trivy_cfg)
    return ",".join(sev.upper() for sev in reversed(blocking))


def _parse_expiry(value: object) -> date | None:
    """Parse an ISO-8601 ``YYYY-MM-DD`` date, or None if unparseable."""
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _exception_targets(
    entry: object,
    image_id: str,
    today: date,
) -> tuple[str, list[str], str | None]:
    """Classify one exception entry for ``image_id``.

    Returns ``(cve, targets, skip_msg)`` where ``targets`` is the subset of
    ``{"trivy", "snyk"}`` the exception applies to and ``skip_msg`` is set when
    the entry is dropped (wrong image, blank CVE, expired/invalid date, or an
    unknown scanner). Fail-safe: a dropped exception suppresses nothing.
    """
    if not isinstance(entry, dict) or entry.get("image_id") != image_id:
        return "", [], None
    cve = str(entry.get("cve_id", "")).strip()
    if not cve:
        return "", [], None
    if not _CVE_RE.match(cve):
        # Reject anything that is not a bare vuln id before it can reach the
        # .trivyignore write. Fail-safe: a malformed id suppresses nothing.
        return cve, [], f"{cve} (malformed cve_id)"
    expiry = _parse_expiry(entry.get("expires"))
    if expiry is None or expiry < today:
        reason = "invalid expires" if expiry is None else "expired"
        return cve, [], f"{cve} ({reason})"
    scanner = str(entry.get("scanner", "")).lower()
    if scanner not in _VALID_SCANNERS:
        return cve, [], f"{cve} (invalid scanner '{scanner}')"
    targets = [s for s in ("trivy", "snyk") if scanner in (s, "both")]
    return cve, targets, None


def _active_exceptions(
    exceptions: list[dict[str, object]],
    image_id: str,
    today: date,
) -> tuple[list[str], list[str], list[str]]:
    """Split non-expired exceptions for ``image_id`` by scanner.

    Returns ``(trivy_cves, snyk_cves, skipped)`` where ``skipped`` records
    entries dropped because they expired or had an invalid ``expires`` date.
    Fail-safe: a dropped exception does not suppress its finding.
    """
    trivy_cves: list[str] = []
    snyk_cves: list[str] = []
    skipped: list[str] = []
    for entry in exceptions:
        cve, targets, skip_msg = _exception_targets(entry, image_id, today)
        if skip_msg:
            skipped.append(skip_msg)
        if "trivy" in targets:
            trivy_cves.append(cve)
        if "snyk" in targets:
            snyk_cves.append(cve)
    return trivy_cves, snyk_cves, skipped


def _render_trivyignore(cves: list[str], image_id: str) -> str:
    """Build the .trivyignore body, one approved CVE per line.

    Pure string construction: the caller (``main``) performs the write next to
    the path guard, and every ``cve`` here has already passed ``_CVE_RE``.
    """
    lines = [
        "# Generated by scripts/load_scanner_policy.py from catalog/policies.yaml.",
        f"# Active, non-expired exceptions for image: {image_id}.",
        "# Do not edit by hand; edit catalog/policies.yaml instead.",
    ]
    lines.extend(cves)
    return "\n".join(lines) + "\n"


def _render_outputs(outputs: dict[str, str]) -> str:
    """Build the key=value block a later workflow step reads from $GITHUB_OUTPUT."""
    return "".join(f"{key}={value}\n" for key, value in outputs.items())


def _parse_policy(text: str) -> dict:
    """Parse and structurally validate the policy YAML text.

    Kept free of file I/O so the read sink stays co-located with the path guard
    in ``main`` (the value reaching ``open`` is the validated path, not a raw
    argument). Raises ``_PolicyError`` on invalid YAML, a non-mapping document,
    or a missing ``scanner_policy`` mapping.
    """
    try:
        policy = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise _PolicyError(f"policy file is not valid YAML: {exc}") from exc
    if not isinstance(policy, dict):
        raise _PolicyError("policy file is not a YAML mapping")
    if not isinstance(policy.get("scanner_policy"), dict):
        raise _PolicyError("policy file is missing a 'scanner_policy' mapping")
    return policy


def _resolve_today(raw: str | None) -> date:
    """Return the reference date, honoring a ``--today`` test override.

    Raises:
        _PolicyError: If an override is given but is not an ISO-8601 date.
    """
    if not raw:
        return datetime.now(timezone.utc).date()
    parsed = _parse_expiry(raw)
    if parsed is None:
        raise _PolicyError(f"invalid --today value: {raw}")
    return parsed


def _build_outputs(
    scanner_policy: dict,
    trivy_cves: list[str],
    snyk_cves: list[str],
    trivyignore_path: Path,
) -> dict[str, str]:
    """Assemble the key=value pairs each downstream scanner step consumes."""
    snyk_cfg = scanner_policy.get("snyk") or {}
    trivy_cfg = scanner_policy.get("trivy") or {}
    cosign_cfg = scanner_policy.get("upstream_cosign") or {}
    identity = str(cosign_cfg.get("expected_identity_regexp", ".*"))
    issuer = str(cosign_cfg.get("expected_issuer_regexp", ".*"))
    return {
        "snyk_threshold": _snyk_threshold(snyk_cfg),
        "trivy_severities": _trivy_severities(trivy_cfg),
        "trivyignore_file": str(trivyignore_path),
        "trivy_exception_count": str(len(trivy_cves)),
        "snyk_exception_cves": ",".join(snyk_cves),
        "cosign_required": "true" if cosign_cfg.get("required") else "false",
        "cosign_identity_regexp": identity,
        "cosign_issuer_regexp": issuer,
        "cosign_identity_pinned": "false" if identity == ".*" else "true",
    }


def _print_trace(image_id: str, outputs: dict[str, str], skipped: list[str]) -> None:
    """Emit a human-readable trace to the job log (stdout, not an output channel)."""
    print(f"Scanner policy for {image_id}:")
    for key, value in outputs.items():
        print(f"  {key}={value}")
    if skipped:
        print(f"  skipped exceptions (fail-safe, still blocking): {skipped}")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Translate catalog/policies.yaml into scanner settings"
    )
    p.add_argument("--policy-file", required=True, help="Path to catalog/policies.yaml")
    p.add_argument("--image-id", required=True, help="Catalog image id being promoted")
    p.add_argument(
        "--trivyignore-out",
        default=".trivyignore",
        help="Path to write the generated .trivyignore",
    )
    p.add_argument(
        "--github-output",
        default=os.environ.get("GITHUB_OUTPUT", ""),
        help="Path to append key=value outputs (default: $GITHUB_OUTPUT)",
    )
    p.add_argument(
        "--today",
        default=None,
        help="Override today's date (YYYY-MM-DD) for deterministic tests",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    allowed = _allowed_roots()

    image_id = args.image_id
    if not _IMAGE_ID_RE.match(image_id):
        return _fail(f"invalid image id: {image_id}")

    try:
        policy_path = _resolve_within(args.policy_file, allowed)
        if not policy_path.is_file():
            return _fail(f"policy file not found: {policy_path}")
        # Every filesystem access happens here in main, next to its path guard,
        # so the taint analysis sees a validated path reaching each sink. The
        # written content is also sanitized at source (_IMAGE_ID_RE, _CVE_RE).
        policy = _parse_policy(policy_path.read_text(encoding="utf-8"))
        today = _resolve_today(args.today)
    except _PolicyError as exc:
        return _fail(str(exc))

    exceptions = policy.get("exceptions") or []
    if not isinstance(exceptions, list):
        return _fail("'exceptions' must be a list")

    trivy_cves, snyk_cves, skipped = _active_exceptions(exceptions, image_id, today)

    trivyignore_path = _resolve_within(args.trivyignore_out, allowed)
    trivyignore_path.write_text(
        _render_trivyignore(trivy_cves, image_id), encoding="utf-8"
    )

    outputs = _build_outputs(
        policy["scanner_policy"], trivy_cves, snyk_cves, trivyignore_path
    )
    _print_trace(image_id, outputs, skipped)

    if args.github_output:
        output_path = _resolve_within(args.github_output, allowed)
        with output_path.open("a", encoding="utf-8") as fh:
            fh.write(_render_outputs(outputs))

    return 0


if __name__ == "__main__":
    sys.exit(main())
