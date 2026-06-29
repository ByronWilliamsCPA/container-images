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
- A2 (scanner policies): complete
- A3 (promotion lock): partially complete — lock file schema, update script
  (`scripts/update_approved_lock.py`), and `update-lock` job in
  `publish-approved-image.yml` are all implemented; bot commit GPG signing is
  deferred pending a dedicated signing key in repo secrets

## Key files

| File | Role |
| --- | --- |
| `catalog/images.yaml` | Image catalog: the authoritative list of images to mirror |
| `catalog/policies.yaml` | Scanner thresholds and CVE exception policy (A2) |
| `catalog/approved-lock.yaml` | Digest-pinned promotion lock (A3) |
| `scripts/validate_catalog_schema.py` | Schema validator for the catalog (run before every PR) |
| `scripts/build_matrix.py` | Builds the GitHub Actions matrix from the catalog |
| `scripts/load_scanner_policy.py` | Translates `policies.yaml` into scanner knobs for A2 |
| `scripts/update_approved_lock.py` | Upserts entries in `approved-lock.yaml` (A3) |
| `.github/workflows/mirror-hardened-images.yml` | A1 mirror pipeline: crane digest-copy, Trivy scan, Cosign sign, SBOM attest |
| `.github/workflows/validate-catalog-schema.yml` | A0 exit gate: schema validator + pytest on every push and PR |
| `.github/workflows/publish-approved-image.yml` | A2 reusable promotion workflow: full scanner policy pipeline |
| `.github/workflows/pr-validation.yml` | Ruff + pytest + pip-audit required PR check |
| `.github/workflows/security-analysis.yml` | Bandit + yamllint required security gate |
| `.github/workflows/codeql.yml` | CodeQL SAST (Python), weekly and on PR |

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

Changes to `.github/workflows/publish-approved-image.yml` (A2) must also preserve:
- the `load_scanner_policy.py` step (policy-driven Snyk/Trivy thresholds)
- the `update-lock` job writing to `catalog/approved-lock.yaml` (A3)

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
