# container-images: Claude Development Context

> **Scope**: Project-local context for `ByronWilliamsCPA/container-images`.
> Global standards are in `~/.claude/CLAUDE.md` and take precedence on conflicts.

## Project context

This repo is a public mirror of hardened container images (DHI and Distroless variants)
for homelab infrastructure. The primary deliverable is a set of signed, SBOM-attested
images published to `ghcr.io/ByronWilliamsCPA/*`.

The catalog is the single source of truth. No image is mirrored unless it has an entry
in `catalog/images.yaml`. Each entry carries an `id` field (e.g. `dhi-python-3.12`) and
a `target` field that maps to the GHCR destination. Workflow files consume the catalog;
they do not hardcode image names.

Active phases:
- A0 (catalog schema and matrix builder): complete
- A1 (crane digest-copy mirror pipeline): complete
- A2 (scanner policies): planned
- A3 (promotion lock): planned

## Key files

| File | Role |
| --- | --- |
| `catalog/images.yaml` | Image catalog: the authoritative list of images to mirror |
| `scripts/validate_catalog_schema.py` | Schema validator for the catalog (run before every PR) |
| `scripts/verify_approved_lock.py` | A3 provenance validator for `catalog/approved-lock.yaml` (schema, source==target digest, catalog cross-reference) |
| `scripts/build_matrix.py` | Builds the GitHub Actions matrix from the catalog |
| `.github/workflows/mirror-hardened-images.yml` | Mirror pipeline: pulls source, copies via crane, signs, attests SBOM |
| `.github/workflows/validate-catalog-schema.yml` | CI job that runs the schema validator on every push |

The Python scripts are glue code only. Keep them small and focused; they are not
application logic.

## Development workflow

### Adding or updating an image

1. Edit `catalog/images.yaml`: add or modify the entry with `id`, `source`, and `target`.
2. Validate locally before opening a PR:
   ```
   python3 scripts/validate_catalog_schema.py
   ```
3. Open a PR targeting `main`. The `validate-catalog-schema` workflow runs automatically.
4. After merge, the mirror workflow runs and publishes the image to GHCR.

### Modifying the mirror pipeline

Changes to `.github/workflows/mirror-hardened-images.yml` must preserve:
- crane digest-copy (not docker pull/push) for reproducible digests
- Cosign signing step
- SBOM attestation step

Test pipeline changes with a draft PR and inspect the Actions run before merging.

## Model selection

See `~/.claude/CLAUDE.md` for the global model selection table. For this repo: use
Haiku for Explore subagent lookups (catalog scanning, file structure mapping).

## RAD markers

Tag assumptions in `catalog/images.yaml` and workflow files that could cause silent
failures in production. Minimum required markers:

- `#ASSUME` when an upstream image tag or digest is expected to remain stable
- `#VERIFY` paired with every `#ASSUME`, stating what to check and how

Example:
```yaml
# #ASSUME upstream tag 3.12-slim is rebuilt nightly; digest may drift
# #VERIFY run `crane digest python:3.12-slim` before each mirror run
```

See `~/.claude/CLAUDE.md` for the full RAD tagging syntax.
