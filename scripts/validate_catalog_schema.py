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


def validate(catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    missing_top = REQUIRED_TOP_LEVEL - set(catalog.keys())
    for field in sorted(missing_top):
        errors.append(error(f"missing required top-level field: {field!r}"))

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

        img_id = img.get("id", f"<index:{i}>")

        missing = REQUIRED_IMAGE_FIELDS - set(img.keys())
        for field in sorted(missing):
            errors.append(error(f"missing required field: {field!r}", img_id))

        if str(img_id) in seen_ids:
            errors.append(error("duplicate id", img_id))
        else:
            seen_ids.add(str(img_id))

        tier = img.get("source_tier", "")
        if tier not in ALLOWED_SOURCE_TIERS:
            errors.append(
                error(
                    f"invalid source_tier {tier!r}; "
                    f"must be one of {sorted(ALLOWED_SOURCE_TIERS)}",
                    img_id,
                )
            )

        crit = img.get("criticality", "")
        if crit not in ALLOWED_CRITICALITY:
            errors.append(
                error(
                    f"invalid criticality {crit!r}; "
                    f"must be one of {sorted(ALLOWED_CRITICALITY)}",
                    img_id,
                )
            )

        cls_status = img.get("classification_status", "")
        if cls_status not in ALLOWED_CLASSIFICATION_STATUS:
            errors.append(
                error(
                    f"invalid classification_status {cls_status!r}; "
                    f"must be one of {sorted(ALLOWED_CLASSIFICATION_STATUS)}",
                    img_id,
                )
            )

        disposition = img.get("disposition", "")
        if disposition not in ALLOWED_DISPOSITION:
            errors.append(
                error(
                    f"invalid disposition {disposition!r}; "
                    f"must be one of {sorted(ALLOWED_DISPOSITION)}",
                    img_id,
                )
            )

        mod = img.get("image_modification", {})
        if isinstance(mod, dict):
            strategy = mod.get("strategy", "")
            if strategy not in ALLOWED_STRATEGIES:
                errors.append(
                    error(
                        f"invalid image_modification.strategy {strategy!r}; "
                        f"must be one of {sorted(ALLOWED_STRATEGIES)}",
                        img_id,
                    )
                )
        else:
            errors.append(error("image_modification must be a mapping", img_id))

        upstream = img.get("upstream", {})
        if isinstance(upstream, dict):
            missing_u = REQUIRED_UPSTREAM_FIELDS - set(upstream.keys())
            for field in sorted(missing_u):
                errors.append(
                    error(f"upstream missing required field: {field!r}", img_id)
                )
        else:
            errors.append(error("upstream must be a mapping", img_id))

        ghcr = img.get("ghcr", {})
        if isinstance(ghcr, dict):
            missing_g = REQUIRED_GHCR_FIELDS - set(ghcr.keys())
            for field in sorted(missing_g):
                errors.append(error(f"ghcr missing required field: {field!r}", img_id))
            ghcr_ref = (
                f"ghcr.io/byronwilliamscpa/{ghcr.get('name', '')}:{ghcr.get('tag', '')}"
            )
            if ghcr_ref in seen_ghcr_refs:
                errors.append(error(f"duplicate GHCR ref: {ghcr_ref}", img_id))
            else:
                seen_ghcr_refs.add(ghcr_ref)
        else:
            errors.append(error("ghcr must be a mapping", img_id))

        plat = img.get("platform_compatibility", {})
        if isinstance(plat, dict):
            missing_p = REQUIRED_PLATFORM_FIELDS - set(plat.keys())
            for field in sorted(missing_p):
                errors.append(
                    error(
                        f"platform_compatibility missing required field: {field!r}",
                        img_id,
                    )
                )
            supported = plat.get("supported", [])
            if not isinstance(supported, list) or not supported:
                errors.append(
                    error(
                        "platform_compatibility.supported must be a non-empty list",
                        img_id,
                    )
                )
        else:
            errors.append(error("platform_compatibility must be a mapping", img_id))

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
