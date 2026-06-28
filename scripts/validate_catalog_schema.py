#!/usr/bin/env python3
"""Validate catalog/images.yaml against the required schema.

Exit codes:
  0  All entries pass validation.
  1  One or more validation errors found.
  2  Catalog file not found or not parseable.

Usage:
  python3 scripts/validate_catalog_schema.py [catalog/images.yaml]
"""

from __future__ import annotations

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

CATALOG_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("catalog/images.yaml")

REQUIRED_TOP_LEVEL = {"apiVersion", "images"}
REQUIRED_IMAGE_FIELDS = {
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
}
ALLOWED_SOURCE_TIERS = {"primary", "distroless"}
ALLOWED_CRITICALITY = {"critical", "high", "medium", "low"}
ALLOWED_CLASSIFICATION_STATUS = {"classified", "pending"}
ALLOWED_DISPOSITION = {
    "mirror_only",
    "custom_derivative",
    "decommission",
    "exception_only",
}
ALLOWED_STRATEGIES = {
    "mirror_only",
    "replace_source",
    "custom_derivative",
    "runtime_only_hardening",
    "debug_split",
    "decommission",
    "exception_only",
}
REQUIRED_UPSTREAM_FIELDS = {"registry", "name", "tag"}
REQUIRED_GHCR_FIELDS = {"name", "tag"}
REQUIRED_PLATFORM_FIELDS = {"default", "supported"}


def error(msg: str, image_id: str = "") -> str:
    prefix = f"[{image_id}] " if image_id else ""
    return f"  ERROR: {prefix}{msg}"


def _validate_top_level(catalog: dict[str, Any]) -> list[str]:
    """Report any missing required top-level fields."""
    missing_top = REQUIRED_TOP_LEVEL - set(catalog.keys())
    return [
        error(f"missing required top-level field: {field!r}")
        for field in sorted(missing_top)
    ]


def _validate_enum_field(
    img: dict[str, Any], field: str, allowed: set[str], img_id: str
) -> list[str]:
    """Validate that an image's enum field holds an allowed value."""
    value = img.get(field, "")
    if value in allowed:
        return []
    return [
        error(f"invalid {field} {value!r}; must be one of {sorted(allowed)}", img_id)
    ]


def _validate_image_modification(img: dict[str, Any], img_id: str) -> list[str]:
    """Validate the image_modification mapping and its strategy value."""
    mod = img.get("image_modification", {})
    if not isinstance(mod, dict):
        return [error("image_modification must be a mapping", img_id)]
    strategy = mod.get("strategy", "")
    if strategy in ALLOWED_STRATEGIES:
        return []
    return [
        error(
            f"invalid image_modification.strategy {strategy!r}; "
            f"must be one of {sorted(ALLOWED_STRATEGIES)}",
            img_id,
        )
    ]


def _validate_upstream(img: dict[str, Any], img_id: str) -> list[str]:
    """Validate the upstream mapping and its required fields."""
    upstream = img.get("upstream", {})
    if not isinstance(upstream, dict):
        return [error("upstream must be a mapping", img_id)]
    missing_u = REQUIRED_UPSTREAM_FIELDS - set(upstream.keys())
    return [
        error(f"upstream missing required field: {field!r}", img_id)
        for field in sorted(missing_u)
    ]


def _validate_ghcr(
    img: dict[str, Any], img_id: str, seen_ghcr_refs: set[str]
) -> list[str]:
    """Validate the ghcr mapping, required fields, and cross-image ref uniqueness."""
    ghcr = img.get("ghcr", {})
    if not isinstance(ghcr, dict):
        return [error("ghcr must be a mapping", img_id)]
    missing_g = REQUIRED_GHCR_FIELDS - set(ghcr.keys())
    errors = [
        error(f"ghcr missing required field: {field!r}", img_id)
        for field in sorted(missing_g)
    ]
    ghcr_ref = f"ghcr.io/byronwilliamscpa/{ghcr.get('name', '')}:{ghcr.get('tag', '')}"
    if ghcr_ref in seen_ghcr_refs:
        errors.append(error(f"duplicate GHCR ref: {ghcr_ref}", img_id))
    else:
        seen_ghcr_refs.add(ghcr_ref)
    return errors


def _validate_platform_compatibility(img: dict[str, Any], img_id: str) -> list[str]:
    """Validate the platform_compatibility mapping and its supported list."""
    plat = img.get("platform_compatibility", {})
    if not isinstance(plat, dict):
        return [error("platform_compatibility must be a mapping", img_id)]
    missing_p = REQUIRED_PLATFORM_FIELDS - set(plat.keys())
    errors = [
        error(f"platform_compatibility missing required field: {field!r}", img_id)
        for field in sorted(missing_p)
    ]
    supported = plat.get("supported", [])
    if not isinstance(supported, list) or not supported:
        errors.append(
            error("platform_compatibility.supported must be a non-empty list", img_id)
        )
    return errors


def _validate_single_image(
    img: dict[str, Any], i: int, seen_ids: set[str], seen_ghcr_refs: set[str]
) -> list[str]:
    """Validate one image entry, accumulating all errors for it."""
    img_id = img.get("id", f"<index:{i}>")

    errors = [
        error(f"missing required field: {field!r}", img_id)
        for field in sorted(REQUIRED_IMAGE_FIELDS - set(img.keys()))
    ]

    if str(img_id) in seen_ids:
        errors.append(error("duplicate id", img_id))
    else:
        seen_ids.add(str(img_id))

    errors.extend(
        _validate_enum_field(img, "source_tier", ALLOWED_SOURCE_TIERS, img_id)
    )
    errors.extend(_validate_enum_field(img, "criticality", ALLOWED_CRITICALITY, img_id))
    errors.extend(
        _validate_enum_field(
            img, "classification_status", ALLOWED_CLASSIFICATION_STATUS, img_id
        )
    )
    errors.extend(_validate_enum_field(img, "disposition", ALLOWED_DISPOSITION, img_id))
    errors.extend(_validate_image_modification(img, img_id))
    errors.extend(_validate_upstream(img, img_id))
    errors.extend(_validate_ghcr(img, img_id, seen_ghcr_refs))
    errors.extend(_validate_platform_compatibility(img, img_id))
    return errors


def validate(catalog: dict[str, Any]) -> list[str]:
    """Validate a parsed catalog mapping, returning all error messages."""
    errors = _validate_top_level(catalog)

    if "images" not in catalog:
        return errors

    images = catalog["images"]
    if not isinstance(images, list):
        errors.append(error("'images' must be a list"))
        return errors

    seen_ids: set[str] = set()
    seen_ghcr_refs: set[str] = set()

    for i, img in enumerate(images):
        if not isinstance(img, dict):
            errors.append(error(f"entry at index {i} is not a mapping"))
            continue
        errors.extend(_validate_single_image(img, i, seen_ids, seen_ghcr_refs))

    return errors


def main() -> None:
    if not CATALOG_PATH.exists():
        print(f"ERROR: catalog not found: {CATALOG_PATH}", file=sys.stderr)
        sys.exit(2)

    try:
        with CATALOG_PATH.open() as fh:
            catalog = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"ERROR: YAML parse error in {CATALOG_PATH}:\n  {exc}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(catalog, dict):
        print(
            f"ERROR: {CATALOG_PATH} must be a YAML mapping at the top level",
            file=sys.stderr,
        )
        sys.exit(2)

    errors = validate(catalog)
    image_count = len(catalog.get("images", []))

    if errors:
        print(
            f"FAIL: {len(errors)} validation error(s) in {CATALOG_PATH}"
            f" ({image_count} images checked):"
        )
        for err in errors:
            print(err)
        sys.exit(1)
    else:
        print(f"PASS: {CATALOG_PATH} is valid ({image_count} images, 0 errors)")


if __name__ == "__main__":
    main()
