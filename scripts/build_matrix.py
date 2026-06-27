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


def main() -> None:
    if not CATALOG_PATH.exists():
        print(f"ERROR: {CATALOG_PATH} not found", file=sys.stderr)
        sys.exit(1)

    with CATALOG_PATH.open() as fh:
        catalog = yaml.safe_load(fh)

    images = catalog.get("images", [])

    dhi = [build_include(img) for img in images if img.get("source_tier") == "primary"]
    distroless = [build_include(img) for img in images if img.get("source_tier") == "distroless"]

    dhi_matrix = json.dumps({"include": dhi}, separators=(",", ":"))
    distroless_matrix = json.dumps({"include": distroless}, separators=(",", ":"))

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as fh:
            fh.write(f"dhi_matrix={dhi_matrix}\n")
            fh.write(f"distroless_matrix={distroless_matrix}\n")
            fh.write(f"dhi_count={len(dhi)}\n")
            fh.write(f"distroless_count={len(distroless)}\n")
    else:
        print(f"dhi_matrix={dhi_matrix}")
        print(f"distroless_matrix={distroless_matrix}")
        print(f"dhi_count={len(dhi)}")
        print(f"distroless_count={len(distroless)}")


if __name__ == "__main__":
    main()
