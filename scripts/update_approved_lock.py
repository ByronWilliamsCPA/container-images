#!/usr/bin/env python3
"""Append or update a promotion entry in catalog/approved-lock.yaml.

Called by the update-lock job in publish-approved-image.yml (A2) after all
security gates pass. Idempotent: re-promoting an image updates the existing
entry rather than duplicating it.

Exit codes:
  0  Lock file updated successfully.
  1  Argument error or file I/O failure.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Update catalog/approved-lock.yaml")
    p.add_argument("--lock-file", required=True, help="Path to approved-lock.yaml")
    p.add_argument("--image-id", required=True, help="Catalog image id field value")
    p.add_argument(
        "--ghcr-ref", required=True, help="Full GHCR ref (name:tag, no digest)"
    )
    p.add_argument("--source-digest", required=True, help="sha256 digest from upstream")
    p.add_argument(
        "--target-digest", required=True, help="sha256 digest on GHCR after copy"
    )
    p.add_argument(
        "--promoted-at", required=True, help="ISO-8601 UTC promotion timestamp"
    )
    p.add_argument("--promoted-by", required=True, help="GitHub Actions run URL")
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    lock_path = Path(args.lock_file)
    if not lock_path.exists():
        print(f"ERROR: lock file not found: {lock_path}", file=sys.stderr)
        return 1

    with lock_path.open() as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        print("ERROR: lock file is not a YAML mapping", file=sys.stderr)
        return 1

    entry: dict[str, str] = {
        "id": args.image_id,
        "ghcr_ref": args.ghcr_ref,
        "source_digest": args.source_digest,
        "target_digest": args.target_digest,
        "promoted_at": args.promoted_at,
        "promoted_by": args.promoted_by,
    }

    promoted: list[dict[str, str]] = data.get("promoted") or []
    updated = False
    for i, existing in enumerate(promoted):
        if existing.get("id") == args.image_id:
            promoted[i] = entry
            updated = True
            print(f"Updated existing lock entry for {args.image_id}")
            break

    if not updated:
        promoted.append(entry)
        print(f"Appended new lock entry for {args.image_id}")

    data["promoted"] = promoted
    data.setdefault("metadata", {})["last_updated"] = args.promoted_at

    with lock_path.open("w") as fh:
        yaml.dump(
            data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True
        )

    print(f"Lock file written: {lock_path} ({len(promoted)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
