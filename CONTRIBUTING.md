# Contributing

## Adding or Updating Images

This repository uses a catalog-first workflow. The source of truth for all
mirrored images is `catalog/images.yaml`.

1. Edit `catalog/images.yaml` following the existing schema (each entry
   specifies `source`, `destination`, and `tag` fields).
2. Validate your changes locally:
   ```bash
   python3 scripts/validate_catalog_schema.py
   ```
3. Open a pull request against `main`. The `validate-catalog-schema` workflow
   runs automatically on every PR.
4. On merge to `main`, the mirror workflow copies each image to GHCR by digest,
   signs it with cosign, and attests an SBOM.

Do not push images directly to GHCR; all images must flow through the mirror
workflow to ensure they are signed and attested.

## Reporting Security Issues

Please see [SECURITY.md](SECURITY.md) for the vulnerability reporting process.
Do not open a public issue for security concerns.
