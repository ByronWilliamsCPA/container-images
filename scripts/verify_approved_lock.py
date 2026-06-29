#!/usr/bin/env python3
"""Verify catalog/approved-lock.yaml against the approved-image catalog.

This is the A3 exit-gate core. Every promotion entry written by
``update_approved_lock.py`` is checked for:

  * schema conformance (the producer field set is present and well typed);
  * the provenance invariant ``source_digest == target_digest`` (the GHCR
    copy must be the exact upstream digest resolved at promotion time);
  * digest format (``sha256:`` + 64 lowercase hex);
  * cross-reference against ``catalog/images.yaml`` -- every promoted ``id``
    must be a catalog id, and its ``ghcr_ref`` must match the reference the
    catalog declares for that id;
  * id uniqueness within the lock.

A deliberately tampered lock (unequal digests, an unapproved id, or a
rewritten ghcr_ref) fails CI here before any downstream consumer trusts it.

Cryptographic verification (lock signature, hash-chain continuity, signer
identity) is defense-in-depth layered on top of this by the publish workflow
and is intentionally out of scope for this schema/provenance gate.

Exit codes:
  0  All entries pass validation.
  1  One or more validation errors found.
  2  A required file is missing or not parseable.

Usage:
  python3 scripts/verify_approved_lock.py \\
      [catalog/approved-lock.yaml] [catalog/images.yaml]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr
    )
    sys.exit(2)

DEFAULT_LOCK_PATH = Path("catalog/approved-lock.yaml")
DEFAULT_CATALOG_PATH = Path("catalog/images.yaml")

# #ASSUME GHCR_NAMESPACE and the ref-derivation in build_catalog_refs match
# validate_catalog_schema.py's literal; the two scripts must change in lockstep
# or the catalog cross-reference silently mismatches every promoted entry.
# #VERIFY grep both scripts for "ghcr.io/byronwilliamscpa" when renaming the org.
GHCR_NAMESPACE = "ghcr.io/byronwilliamscpa"
EXPECTED_KIND = "ApprovedImageLock"

REQUIRED_TOP_LEVEL = {"apiVersion", "kind", "promoted"}
REQUIRED_ENTRY_FIELDS = {
    "id",
    "ghcr_ref",
    "source_digest",
    "target_digest",
    "promoted_at",
    "promoted_by",
}
# Docker/OCI content digests: sha256 plus exactly 64 lowercase hex characters.
# Unanchored and matched with re.fullmatch (below) so a trailing newline cannot
# slip through: the `$` anchor matches just before a final '\n', which would let
# "sha256:<64hex>\n" pass the format gate.
# #ASSUME only sha256 digests are emitted; crane/cosign resolve sha256 today.
# #VERIFY extend the alternation if the publish pipeline adopts sha512.
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def error(msg: str, entry_id: str = "") -> str:
    prefix = f"[{entry_id}] " if entry_id else ""
    return f"  ERROR: {prefix}{msg}"


def build_catalog_refs(catalog: dict[str, Any]) -> dict[str, str]:
    """Map each catalog id to the fully-qualified GHCR ref the catalog declares.

    The ref is derived the same way ``validate_catalog_schema.py`` derives it,
    so a lock entry's ``ghcr_ref`` can be compared against the single source of
    truth rather than trusted as written.
    """
    refs: dict[str, str] = {}
    images = catalog.get("images", [])
    if not isinstance(images, list):
        return refs
    for img in images:
        if not isinstance(img, dict):
            continue
        img_id = img.get("id")
        ghcr = img.get("ghcr", {})
        if not isinstance(img_id, str) or not isinstance(ghcr, dict):
            continue
        refs[img_id] = f"{GHCR_NAMESPACE}/{ghcr.get('name', '')}:{ghcr.get('tag', '')}"
    return refs


def _validate_top_level(lock: dict[str, Any]) -> list[str]:
    """Report missing required top-level fields and a wrong ``kind`` value."""
    # Treat a present-but-null field (YAML `field:` with no value) the same as a
    # missing one. Otherwise the key-membership check passes while the value-level
    # checks below skip on None, letting a nulled apiVersion/kind/promoted bypass
    # the gate.
    errors = [
        error(f"missing required top-level field: {field!r}")
        for field in sorted(REQUIRED_TOP_LEVEL)
        if lock.get(field) is None
    ]
    kind = lock.get("kind")
    if kind is not None and kind != EXPECTED_KIND:
        errors.append(error(f"invalid kind {kind!r}; must be {EXPECTED_KIND!r}"))
    return errors


def _validate_digests(entry: dict[str, Any], entry_id: str) -> list[str]:
    """Validate digest format and the source==target provenance invariant."""
    errors: list[str] = []
    source = entry.get("source_digest")
    target = entry.get("target_digest")

    for field, value in (("source_digest", source), ("target_digest", target)):
        if value is not None and not (
            isinstance(value, str) and DIGEST_RE.fullmatch(value)
        ):
            errors.append(
                error(
                    f"{field} {value!r} is not a valid sha256 digest "
                    "(expected 'sha256:' + 64 lowercase hex chars)",
                    entry_id,
                )
            )

    # Only assert equality once both are present; missing-field errors are
    # reported separately so we do not double-report here.
    if source is not None and target is not None and source != target:
        errors.append(
            error(
                f"source_digest != target_digest ({source} vs {target}); "
                "the GHCR copy must be the exact upstream digest",
                entry_id,
            )
        )
    return errors


def _validate_catalog_link(
    entry: dict[str, Any], entry_id: str, catalog_refs: dict[str, str]
) -> list[str]:
    """Validate that the entry id is approved and its ghcr_ref is the catalog's."""
    if entry_id not in catalog_refs:
        return [
            error(
                f"id {entry_id!r} is not present in the approved image catalog",
                entry_id,
            )
        ]
    expected_ref = catalog_refs[entry_id]
    actual_ref = entry.get("ghcr_ref")
    if actual_ref is not None and actual_ref != expected_ref:
        return [
            error(
                f"ghcr_ref {actual_ref!r} does not match the catalog ref "
                f"{expected_ref!r} for this id",
                entry_id,
            )
        ]
    return []


# Required fields that must be plain strings. Digests are excluded here because
# _validate_digests format-checks them; the rest get a type check so the "well
# typed" schema promise holds for the audit-trail fields too.
STRING_FIELDS = ("id", "ghcr_ref", "promoted_at", "promoted_by")


def _validate_field_types(entry: dict[str, Any], entry_id: str) -> list[str]:
    """Reject required string fields that are present but not strings."""
    errors: list[str] = []
    for field in STRING_FIELDS:
        value = entry.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(
                error(
                    f"{field} must be a string, got {type(value).__name__}",
                    entry_id,
                )
            )
    return errors


def _validate_entry(
    entry: Any,
    index: int,
    catalog_refs: dict[str, str],
    seen_ids: set[str],
) -> list[str]:
    """Validate one promotion entry, accumulating all of its errors."""
    if not isinstance(entry, dict):
        return [error(f"entry at index {index} is not a mapping")]

    entry_id = entry.get("id", f"<index:{index}>")

    # A present-but-null field counts as missing (see _validate_top_level): the
    # value-level checks below skip on None, so without this a nulled
    # source_digest/target_digest/ghcr_ref would bypass the provenance gate.
    errors = [
        error(f"missing or null required field: {field!r}", entry_id)
        for field in sorted(REQUIRED_ENTRY_FIELDS)
        if entry.get(field) is None
    ]

    if str(entry_id) in seen_ids:
        errors.append(error("duplicate id", entry_id))
    else:
        seen_ids.add(str(entry_id))

    errors.extend(_validate_field_types(entry, str(entry_id)))
    errors.extend(_validate_digests(entry, str(entry_id)))
    if entry.get("id") is not None:
        errors.extend(_validate_catalog_link(entry, str(entry_id), catalog_refs))
    return errors


def validate(lock: dict[str, Any], catalog: dict[str, Any]) -> list[str]:
    """Validate a parsed lock against a parsed catalog, returning all errors."""
    errors = _validate_top_level(lock)

    promoted = lock.get("promoted")
    if promoted is None:
        return errors
    if not isinstance(promoted, list):
        errors.append(error("'promoted' must be a list"))
        return errors

    # Surface a structurally broken catalog explicitly. Without this, a non-list
    # `images` yields an empty ref map and every entry fails with a misleading
    # "id not present in catalog" instead of pointing at the real cause.
    images = catalog.get("images")
    if not isinstance(images, list):
        errors.append(
            error(
                "catalog 'images' is missing or not a list; "
                "cannot verify lock entries against it"
            )
        )

    catalog_refs = build_catalog_refs(catalog)
    seen_ids: set[str] = set()
    for i, entry in enumerate(promoted):
        errors.extend(_validate_entry(entry, i, catalog_refs, seen_ids))
    return errors


def _load_yaml_mapping(path: Path, label: str) -> dict[str, Any]:
    """Load a YAML file that must exist and parse to a top-level mapping.

    The path is resolved and confirmed to be a regular ``.yaml``/``.yml`` file
    immediately before it is opened, co-locating the validation barrier with the
    filesystem sink so a faulty CLI argument cannot reach ``open()`` unvalidated
    (SonarCloud S8707).
    """
    resolved = path.resolve()
    if resolved.suffix not in {".yaml", ".yml"} or not resolved.is_file():
        print(f"ERROR: {label} not found or not a YAML file: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with resolved.open() as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        print(f"ERROR: cannot read or parse {path}:\n  {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"ERROR: {path} must be a YAML mapping at the top level", file=sys.stderr)
        sys.exit(2)
    return data


def main() -> None:
    # Parse argv here (not at import time) so the module has no import-time
    # side effects and main() is exercisable under pytest.
    lock_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOCK_PATH
    catalog_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_CATALOG_PATH

    lock = _load_yaml_mapping(lock_path, "lock file")
    catalog = _load_yaml_mapping(catalog_path, "catalog")

    errors = validate(lock, catalog)
    entry_count = len(lock.get("promoted") or [])

    if errors:
        print(
            f"FAIL: {len(errors)} validation error(s) in {lock_path}"
            f" ({entry_count} promotion entries checked):"
        )
        for err in errors:
            print(err)
        sys.exit(1)
    print(f"PASS: {lock_path} is valid ({entry_count} entries, 0 errors)")
    sys.exit(0)


if __name__ == "__main__":
    main()
