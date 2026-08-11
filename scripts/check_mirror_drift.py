#!/usr/bin/env python3
"""Report drift between catalog/images.yaml, GHCR, and the upstream registries.

Three kinds of drift are reported:

  STALE      a mirrored tag whose platform digest no longer matches upstream,
             i.e. upstream has rebuilt and the mirror has not caught up
  MISSING    a catalog entry with no corresponding published GHCR tag
  ORPHAN     a published GHCR tag with no catalog entry, so the catalog-driven
             mirror matrix never refreshes it
  STALE PIN  a catalog `upstream.digest` value that no longer resolves

The staleness comparator is deliberately the same assertion the mirror job
makes after `crane copy`: the platform-resolved digest on each side. Build
timestamps are not usable here, because reproducibly-built images (Google
Distroless) report `created: 1970-01-01T00:00:00Z` forever and would compare
equal on both sides regardless of drift.

Requires `crane` on PATH, and registry credentials for any upstream that
needs them (`crane auth login dhi.io ...`).

Usage:
  python3 scripts/check_mirror_drift.py [catalog/images.yaml]

Exits 1 if any drift is found, 0 if the mirror is current.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required.", file=sys.stderr)
    sys.exit(1)

CATALOG_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("catalog/images.yaml")
GHCR_OWNER = "byronwilliamscpa"
CRANE_TIMEOUT = 120


def is_artifact_tag(tag: str) -> bool:
    """True for Cosign signature/attestation tags, which are not images.

    Cosign publishes its artifacts as tags derived from the subject digest
    (`sha256-<hex>`, optionally with a `.sig`/`.att` suffix). They are never
    catalog entries, so reporting them as orphans would be pure noise.
    """
    return tag.startswith("sha256-")


def diff_tags(declared: set[str], published: set[str]) -> tuple[list[str], list[str]]:
    """Return (missing, orphans) for one GHCR repository.

    Both directions matter. Declared-but-absent means the pipeline never
    published something the catalog promises. Present-but-undeclared means an
    image consumers can pull that no pipeline run will ever refresh.
    """
    missing = sorted(declared - published)
    orphans = sorted(t for t in published - declared if not is_artifact_tag(t))
    return missing, orphans


def crane(args: list[str]) -> str | None:
    """Run crane and return stdout, or None if the command failed."""
    try:
        result = subprocess.run(
            ["crane", *args],
            capture_output=True,
            text=True,
            timeout=CRANE_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"  ! crane {' '.join(args)}: {exc}", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(
            f"  ! crane {' '.join(args)}: {result.stderr.strip()[:200]}",
            file=sys.stderr,
        )
        return None
    return result.stdout.strip()


def parse_catalog(path: Path) -> list[dict]:
    """Flatten the catalog into the fields this check needs."""
    catalog = yaml.safe_load(path.read_text())
    entries = []
    for img in catalog.get("images", []):
        platform = img.get("platform_compatibility", {}).get("default", "linux/amd64")
        entries.append(
            {
                "id": img["id"],
                "source": f"{img['upstream']['registry']}/{img['upstream']['name']}"
                f":{img['upstream']['tag']}",
                "target": f"ghcr.io/{GHCR_OWNER}/{img['ghcr']['name']}"
                f":{img['ghcr']['tag']}",
                "ghcr_name": img["ghcr"]["name"],
                "ghcr_tag": str(img["ghcr"]["tag"]),
                "platform": platform,
                "pin": img["upstream"].get("digest"),
            }
        )
    return entries


def check_pins(entries: list[dict]) -> list[tuple]:
    """Report catalog `upstream.digest` pins that no longer resolve.

    These pins are documentation: build_matrix.py does not emit the field, so
    the mirror copies by tag and never reads them. A pin nobody reads still
    rots, and a rotted pin next to a `#VERIFY` marker reads as a verified fact
    when it is the opposite. Accept either the index digest or the
    platform digest, since the catalog does not say which one was recorded.
    """
    drifted = []
    for entry in (e for e in entries if e["pin"]):
        index = crane(["digest", entry["source"]])
        platform = crane(["digest", entry["source"], "--platform", entry["platform"]])
        resolved = {d for d in (index, platform) if d}
        if resolved and entry["pin"] not in resolved:
            drifted.append((entry["id"], entry["pin"], sorted(resolved)))
    return drifted


def check_staleness(entries: list[dict]) -> tuple[list[tuple], list[str]]:
    """Compare each entry's upstream platform digest against the mirror's."""
    stale, unchecked = [], []
    for entry in entries:
        source = crane(["digest", entry["source"], "--platform", entry["platform"]])
        target = crane(["digest", entry["target"]])
        if source is None or target is None:
            unchecked.append(entry["id"])
            continue
        if source != target:
            stale.append((entry["id"], entry["target"], target, source))
    return stale, unchecked


def check_coverage(entries: list[dict]) -> tuple[list[str], list[str]]:
    """Diff catalog-declared tags against published tags, in both directions."""
    declared: dict[str, set[str]] = {}
    for entry in entries:
        declared.setdefault(entry["ghcr_name"], set()).add(entry["ghcr_tag"])

    missing_all, orphans_all = [], []
    for name, tags in sorted(declared.items()):
        listing = crane(["ls", f"ghcr.io/{GHCR_OWNER}/{name}"])
        if listing is None:
            continue
        published = {t for t in listing.splitlines() if t}
        missing, orphans = diff_tags(tags, published)
        missing_all += [f"{name}:{t}" for t in missing]
        orphans_all += [f"{name}:{t}" for t in orphans]
    return missing_all, orphans_all


def main() -> int:
    if not CATALOG_PATH.is_file():
        print(f"ERROR: catalog not found: {CATALOG_PATH}", file=sys.stderr)
        return 2

    entries = parse_catalog(CATALOG_PATH)
    print(f"Checking {len(entries)} catalog entries...\n")

    stale, unchecked = check_staleness(entries)
    missing, orphans = check_coverage(entries)
    drifted_pins = check_pins(entries)

    if stale:
        print(f"STALE ({len(stale)}) -- upstream has rebuilt, mirror has not:")
        for img_id, target, mirror_digest, upstream_digest in stale:
            print(f"  {target}  [{img_id}]")
            print(f"      mirror   {mirror_digest}")
            print(f"      upstream {upstream_digest}")
    if missing:
        print(f"\nMISSING ({len(missing)}) -- in catalog, not published:")
        for ref in missing:
            print(f"  {ref}")
    if orphans:
        print(f"\nORPHAN ({len(orphans)}) -- published, no catalog entry:")
        for ref in orphans:
            print(f"  {ref}")
    if drifted_pins:
        print(
            f"\nSTALE PIN ({len(drifted_pins)}) -- upstream.digest no longer resolves:"
        )
        for img_id, pin, resolved in drifted_pins:
            print(f"  {img_id}")
            print(f"      pinned   {pin}")
            for digest in resolved:
                print(f"      actual   {digest}")
    if unchecked:
        print(f"\nUNCHECKED ({len(unchecked)}) -- registry query failed:")
        for img_id in unchecked:
            print(f"  {img_id}")

    if not (stale or missing or orphans or drifted_pins):
        print("No drift: every catalog entry matches upstream.")

    # Unchecked entries are not drift, but they are not proof of health either;
    # a credential or network failure must not read as a clean bill.
    return 1 if (stale or missing or orphans or drifted_pins or unchecked) else 0


if __name__ == "__main__":
    sys.exit(main())
