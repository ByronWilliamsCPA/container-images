# Contributing

## Adding or Updating Images

This repository uses a catalog-first workflow. The source of truth for all
mirrored images is `catalog/images.yaml`.

1. Edit `catalog/images.yaml` following the existing schema (each entry has an
   `id`, a `source_tier`, an `upstream` block of `registry`, `name` and `tag`,
   and a `ghcr` block of `name` and `tag`).
   - `source_tier` is `primary` (`dhi.io`), `distroless` (`gcr.io`) or `vendor`
     (`docker.io`); each tier may only use its own registry.
   - A `vendor` entry (third-party application image, ghcr name
     `vendor-<component>`) must use an immutable version tag and must carry
     `upstream.digest` (`sha256:<64 hex>`, from `crane digest`). It is a
     transport copy of upstream, not a hardened image.
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
