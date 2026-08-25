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


class _IndentedDumper(yaml.Dumper):
    """Dumper that indents block sequences under their parent key.

    PyYAML's default emitter places ``-`` items at the parent key's indent
    (indentless), which yamllint's ``indent-sequences: true`` rule rejects
    (``wrong indentation: expected 2 but found 0``). Forcing ``indentless`` off
    makes the emitted lock file match the repo's YAML style, so the generated
    entry passes the YAML Lint / Security Gate checks on its own promotion PR.
    """

    def increase_indent(self, flow: bool = False, indentless: bool = False):  # noqa: FBT001, FBT002
        return super().increase_indent(flow, False)


def _resolve_lock_path(lock_file: str) -> Path:
    """Resolve lock_file and confirm it stays inside the current working tree.

    The lock path arrives as a CLI argument and is therefore untrusted. A
    traversal value (e.g. ``../../etc/passwd``) would otherwise let a faulty or
    hostile invocation read or overwrite files outside the repository. Resolving
    against ``cwd`` and asserting containment closes that path-injection vector.

    Raises:
        SystemExit: If the resolved path escapes the repository root.
    """
    base = Path.cwd().resolve()
    candidate = (base / lock_file).resolve()
    if candidate != base and base not in candidate.parents:
        print(
            f"ERROR: lock file path escapes repository root: {lock_file}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return candidate


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
    """Upsert one promotion entry into the lock file and write it back.

    Reads the lock file, replaces the entry whose ``id`` matches ``--image-id``
    (or appends a new one), stamps ``metadata.last_updated``, and writes the
    result atomically. Returns 0 on success, 1 on any argument or I/O error.
    """
    args = _parse_args()

    lock_path = _resolve_lock_path(args.lock_file)
    if not lock_path.is_file():
        print(
            f"ERROR: lock file not found or not a file: {lock_path}",
            file=sys.stderr,
        )
        return 1

    try:
        with lock_path.open() as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        print(f"ERROR: lock file is not valid YAML: {exc}", file=sys.stderr)
        return 1

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
    if not isinstance(promoted, list):
        print("ERROR: 'promoted' is present but is not a list", file=sys.stderr)
        return 1
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

    # Write to a temp file then atomically replace, so a failed dump never
    # truncates the canonical lock file (which the workflow would then commit).
    tmp_path = lock_path.with_suffix(lock_path.suffix + ".tmp")
    with tmp_path.open("w") as fh:
        yaml.dump(
            data,
            fh,
            Dumper=_IndentedDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            indent=2,
        )
    tmp_path.replace(lock_path)

    print(f"Lock file written: {lock_path} ({len(promoted)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
