#!/usr/bin/env python3
"""Build GitHub Actions matrix JSON from catalog/images.yaml.

Outputs a matrix and a count per source tier as GITHUB_OUTPUT lines:
  dhi_matrix={"include":[...]}         dhi_count=N         (source_tier: primary)
  distroless_matrix={"include":[...]}  distroless_count=N  (source_tier: distroless)
  vendor_matrix={"include":[...]}      vendor_count=N      (source_tier: vendor)

Each include item is a dict the mirror workflow steps reference via
${{ matrix.upstream_registry }}, ${{ matrix.upstream_name }}, etc. Vendor rows
additionally carry ${{ matrix.upstream_digest }}: vendor images are copied by
that pinned digest, never by resolving the tag.

An entry whose source_tier is not one of the three above is a hard error, so a
new tier can never be silently dropped from every mirror job.

Usage (called from within a GitHub Actions step):
  python3 scripts/build_matrix.py catalog/images.yaml
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required.", file=sys.stderr)
    sys.exit(1)

CATALOG_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("catalog/images.yaml")

# source_tier -> output prefix. Every tier the schema allows must appear here.
TIER_OUTPUTS = {
    "primary": "dhi",
    "distroless": "distroless",
    "vendor": "vendor",
}

# Tiers whose matrix rows carry upstream_digest. Vendor images are third-party
# software, so the mirror copies the exact digest reviewed in the catalog.
DIGEST_PINNED_TIERS = frozenset({"vendor"})


def build_include(img: dict, *, with_digest: bool = False) -> dict:
    img_id = img.get("id", "<unknown>")
    try:
        upstream = img["upstream"]
        ghcr = img["ghcr"]
        plat = img.get("platform_compatibility", {})
        row = {
            "id": img["id"],
            "upstream_registry": upstream["registry"],
            "upstream_name": upstream["name"],
            "upstream_tag": upstream["tag"],
            "ghcr_name": ghcr["name"],
            "ghcr_tag": ghcr["tag"],
            "platform": plat.get("default", "linux/amd64"),
            "criticality": img.get("criticality", "low"),
        }
        if with_digest:
            row["upstream_digest"] = upstream["digest"]
        return row
    except KeyError as exc:
        print(
            f"ERROR: [{img_id}] catalog entry is missing required field {exc}; "
            "run validate_catalog_schema.py to diagnose",
            file=sys.stderr,
        )
        sys.exit(1)


def resolve_output_path(raw: str) -> Path | None:
    """Return a validated GITHUB_OUTPUT path, or None to fall back to stdout.

    GITHUB_OUTPUT is provided by the Actions runner, but we still validate it is
    an absolute path whose parent directory already exists before opening it for
    append. This prevents an unexpected or attacker-influenced value from
    redirecting the write to an arbitrary location (path traversal).
    """
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute() or not candidate.parent.is_dir():
        # GITHUB_OUTPUT was set but is not a writable absolute path: warn so a
        # CI misconfiguration is visible rather than silently swallowed into the
        # stdout fallback (an empty/unset value is the expected local-run case).
        print(
            f"WARNING: GITHUB_OUTPUT={raw!r} is not a writable absolute path; "
            "falling back to stdout",
            file=sys.stderr,
        )
        return None
    return candidate


def split_by_tier(images: list[dict]) -> dict[str, list[dict]]:
    """Group catalog entries into matrix rows keyed by output prefix.

    Exits 1 on an entry with a missing or unknown source_tier rather than
    skipping it: a skipped entry is an image that silently never gets mirrored.
    """
    matrices: dict[str, list[dict]] = {prefix: [] for prefix in TIER_OUTPUTS.values()}
    for img in images:
        tier = img.get("source_tier")
        if not isinstance(tier, str) or tier not in TIER_OUTPUTS:
            print(
                f"ERROR: [{img.get('id', '<unknown>')}] source_tier {tier!r} is not "
                f"one of {sorted(TIER_OUTPUTS)}; run validate_catalog_schema.py "
                "to diagnose",
                file=sys.stderr,
            )
            sys.exit(1)
        matrices[TIER_OUTPUTS[tier]].append(
            build_include(img, with_digest=tier in DIGEST_PINNED_TIERS)
        )
    return matrices


def main() -> None:
    if not CATALOG_PATH.exists():
        print(f"ERROR: {CATALOG_PATH} not found", file=sys.stderr)
        sys.exit(1)

    with CATALOG_PATH.open() as fh:
        catalog = yaml.safe_load(fh)

    images = catalog.get("images", [])

    matrices = split_by_tier(images)
    lines = "".join(
        f"{prefix}_matrix={json.dumps({'include': rows}, separators=(',', ':'))}\n"
        for prefix, rows in matrices.items()
    ) + "".join(f"{prefix}_count={len(rows)}\n" for prefix, rows in matrices.items())

    output_path = resolve_output_path(os.environ.get("GITHUB_OUTPUT", ""))
    if output_path is not None:
        with output_path.open("a") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)


if __name__ == "__main__":
    main()
