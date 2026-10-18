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
ALLOWED_SOURCE_TIERS = {"primary", "distroless", "vendor"}
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

# RT-2: only these registries may feed the mirror, and each source tier has
# exactly one. Anything else (a typo, a look-alike, an attacker-controlled
# host, or a tier pointed at another tier's registry) is rejected outright.
# A vendor entry cannot be smuggled in as a hardened-base mirror, or the
# reverse, by choosing a registry that the other tier owns.
TIER_REGISTRIES: dict[str, frozenset[str]] = {
    "primary": frozenset({"dhi.io"}),
    "distroless": frozenset({"gcr.io"}),
    "vendor": frozenset({"docker.io"}),
}

# Tiers whose upstream is third-party application software rather than a
# hardened base. Their bytes are copied as published, so the entry MUST pin
# an immutable digest and MUST NOT track a floating tag.
DIGEST_REQUIRED_TIERS = frozenset({"vendor"})

# RT-6: a floating tag is not a durable pin. When upstream.tag is one of these,
# the entry MUST also carry an upstream.digest so the mirror copies exactly the
# bytes reviewed here, not whatever the tag later drifts to.
MUTABLE_TAGS = {
    "latest",
    "stable",
    "edge",
    "main",
    "master",
    "nightly",
    "dev",
    "rolling",
}

# Value-shape patterns (RT-2, RT-7).
# Upstream repo path: lowercase OCI path components joined by '/'. Rejects '..'
# traversal, leading/trailing slashes, and uppercase/space injection.
_UPSTREAM_NAME_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
# ghcr.name is published UNDER ghcr.io/byronwilliamscpa/. Constrain it to a
# single path segment so an entry can never traverse out of the org namespace.
_GHCR_NAME_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
# OCI tag grammar: [A-Za-z0-9_][A-Za-z0-9._-]{0,127}.
_TAG_RE = re.compile(r"^\w[\w._-]{0,127}$", re.ASCII)
# Docker Hub repositories are always <namespace>/<repo> (official images live
# under library/). A bare name or a deeper path is not a Hub repository.
_DOCKER_HUB_NAME_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*$"
)
# Manifest/index digest.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    """True only when value is a string fully matching pattern.

    Guards against non-string YAML values (ints, lists, None) that would
    otherwise raise inside re.match and crash validation.
    """
    return isinstance(value, str) and pattern.fullmatch(value) is not None


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
    # isinstance guard: an unhashable YAML value (a list or mapping) would raise
    # TypeError in the set lookup instead of producing a validation error.
    if isinstance(value, str) and value in allowed:
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


def _allowed_registries(tier: str | None) -> frozenset[str]:
    """Registries a source tier may use; every tier's set for an unknown tier.

    An invalid source_tier is reported by the enum check; falling back to the
    union here keeps that single mistake from also raising a registry error.
    """
    if tier in TIER_REGISTRIES:
        return TIER_REGISTRIES[tier]
    return frozenset().union(*TIER_REGISTRIES.values())


def _validate_upstream_registry(
    upstream: dict[str, Any], tier: str | None, img_id: str
) -> list[str]:
    """Validate upstream.registry against the registries its tier may use."""
    registry = upstream.get("registry")
    allowed = _allowed_registries(tier)
    if registry in allowed:
        return []
    scope = f" for source_tier {tier!r}" if tier in TIER_REGISTRIES else ""
    return [
        error(
            f"upstream.registry {registry!r} is not allowed{scope}; "
            f"must be one of {sorted(allowed)}",
            img_id,
        )
    ]


def _validate_upstream_name(upstream: dict[str, Any], img_id: str) -> list[str]:
    """Validate upstream.name, applying Docker Hub's <namespace>/<repo> shape."""
    name = upstream.get("name")
    if not _matches(_UPSTREAM_NAME_RE, name):
        return [
            error(
                f"upstream.name {name!r} is not a valid image path "
                "(lowercase segments, no traversal)",
                img_id,
            )
        ]
    if upstream.get("registry") == "docker.io" and not _matches(
        _DOCKER_HUB_NAME_RE, name
    ):
        return [
            error(
                f"upstream.name {name!r} is not a Docker Hub repository; "
                "expected <namespace>/<repo>",
                img_id,
            )
        ]
    return []


def _validate_upstream_pin(
    upstream: dict[str, Any], tier: str | None, img_id: str
) -> list[str]:
    """Validate upstream.tag and upstream.digest, including the pin rules."""
    errors: list[str] = []

    tag = upstream.get("tag")
    if not _matches(_TAG_RE, tag):
        errors.append(error(f"upstream.tag {tag!r} is not a valid tag", img_id))

    digest = upstream.get("digest")
    digest_ok = _matches(_DIGEST_RE, digest)
    if digest is not None and not digest_ok:
        errors.append(
            error(f"upstream.digest {digest!r} must be sha256:<64 hex>", img_id)
        )

    is_mutable = isinstance(tag, str) and tag.lower() in MUTABLE_TAGS

    if tier in DIGEST_REQUIRED_TIERS:
        # Vendor images are third-party software copied as published. The
        # digest is the pin of record whatever the tag says, and a floating tag
        # would publish a moving target under this org's namespace.
        if is_mutable:
            errors.append(
                error(
                    f"upstream.tag {tag!r} is mutable and not allowed for "
                    f"source_tier {tier!r}; use an immutable version tag",
                    img_id,
                )
            )
        if digest is None:
            errors.append(
                error(
                    f"upstream.digest is required for source_tier {tier!r} "
                    "(sha256:<64 hex>)",
                    img_id,
                )
            )
    elif is_mutable and not digest_ok:
        # RT-6: a floating tag drifts after review. Require an explicit digest
        # so the mirror copies exactly the bytes vetted here, never whatever
        # 'latest' becomes.
        errors.append(
            error(
                f"upstream.tag {tag!r} is mutable; pin upstream.digest "
                "(sha256:...) so the mirror cannot drift",
                img_id,
            )
        )
    return errors


def _validate_upstream(img: dict[str, Any], img_id: str) -> list[str]:
    """Validate the upstream mapping: required fields, value shapes, digest pin."""
    upstream = img.get("upstream", {})
    if not isinstance(upstream, dict):
        return [error("upstream must be a mapping", img_id)]

    # A non-string tier (e.g. a YAML list) is reported by the enum check; here
    # it is treated as unknown so the set lookups below cannot raise TypeError.
    raw_tier = img.get("source_tier")
    tier = raw_tier if isinstance(raw_tier, str) else None
    errors = [
        error(f"upstream missing required field: {field!r}", img_id)
        for field in sorted(REQUIRED_UPSTREAM_FIELDS - set(upstream.keys()))
    ]
    errors.extend(_validate_upstream_registry(upstream, tier, img_id))
    errors.extend(_validate_upstream_name(upstream, img_id))
    errors.extend(_validate_upstream_pin(upstream, tier, img_id))
    return errors


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

    ghcr_name = ghcr.get("name")
    if not _matches(_GHCR_NAME_RE, ghcr_name):
        errors.append(
            error(
                f"ghcr.name {ghcr_name!r} must be a single lowercase path "
                "segment (no '/', no '..' traversal)",
                img_id,
            )
        )

    ghcr_tag = ghcr.get("tag")
    if not _matches(_TAG_RE, ghcr_tag):
        errors.append(error(f"ghcr.tag {ghcr_tag!r} is not a valid tag", img_id))

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
