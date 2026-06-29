#!/usr/bin/env python3
"""Build GitHub Actions matrix JSON from catalog/images.yaml.

Outputs two GITHUB_OUTPUT lines:
  dhi_matrix={"include":[...]}
  distroless_matrix={"include":[...]}

Each include item is a dict the mirror workflow steps reference via
${{ matrix.upstream_registry }}, ${{ matrix.upstream_name }}, etc.

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


def build_include(img: dict) -> dict:
    img_id = img.get("id", "<unknown>")
    try:
        upstream = img["upstream"]
        ghcr = img["ghcr"]
        plat = img.get("platform_compatibility", {})
        return {
            "id": img["id"],
            "upstream_registry": upstream["registry"],
            "upstream_name": upstream["name"],
            "upstream_tag": upstream["tag"],
            "ghcr_name": ghcr["name"],
            "ghcr_tag": ghcr["tag"],
            "platform": plat.get("default", "linux/amd64"),
            "criticality": img.get("criticality", "low"),
        }
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


def main() -> None:
    if not CATALOG_PATH.exists():
        print(f"ERROR: {CATALOG_PATH} not found", file=sys.stderr)
        sys.exit(1)

    with CATALOG_PATH.open() as fh:
        catalog = yaml.safe_load(fh)

    images = catalog.get("images", [])

    dhi = [build_include(img) for img in images if img.get("source_tier") == "primary"]
    distroless = [
        build_include(img) for img in images if img.get("source_tier") == "distroless"
    ]

    dhi_matrix = json.dumps({"include": dhi}, separators=(",", ":"))
    distroless_matrix = json.dumps({"include": distroless}, separators=(",", ":"))

    lines = (
        f"dhi_matrix={dhi_matrix}\n"
        f"distroless_matrix={distroless_matrix}\n"
        f"dhi_count={len(dhi)}\n"
        f"distroless_count={len(distroless)}\n"
    )

    output_path = resolve_output_path(os.environ.get("GITHUB_OUTPUT", ""))
    if output_path is not None:
        with output_path.open("a") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)


if __name__ == "__main__":
    main()
