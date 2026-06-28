# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-06-27

### Changed

- Replace docker pull/push with crane digest-copy in the mirror workflow to
  close the TOCTOU window between image pull and push (commit 00521aa).

## [0.1.0] - 2026-06-27

### Added

- Image catalog at `catalog/images.yaml` with JSON Schema validation.
- Matrix builder script for dynamically generating the CI mirror matrix.
- Schema validator script (`scripts/validate_catalog_schema.py`).
- Initial mirror workflow for DHI and Distroless hardened container images.
- Cosign keyless signing (Sigstore, GitHub Actions OIDC) for all mirrored images.
- Syft SBOM attestation (CycloneDX format) for all mirrored images.
