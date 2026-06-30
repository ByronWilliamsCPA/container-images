# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- A3 approved-lock provenance validator (`scripts/verify_approved_lock.py`),
  wired into the required Validate Catalog Schema gate. It verifies every
  promotion entry in `catalog/approved-lock.yaml`: schema conformance, the
  `source_digest == target_digest` provenance invariant, digest format, and a
  catalog cross-reference of each promoted `id` and `ghcr_ref`.

### Security

- Stop minting cosign signatures and SBOM attestations in the live mirror until
  upstream-identity verification exists (RT-1 interim, ADR-012). A
  `MIRROR_SIGNING_ENABLED` kill-switch (default `false`) gates all four Sign/Attest
  steps in `mirror-hardened-images.yml`, while `crane copy`, digest-equality assert,
  Trivy scan, and SBOM generation still run. Signing previously minted this org's
  keyless identity over unverified upstream bytes (trust laundering); disabling it
  removes false trust, not a working dependency. Re-enable once the shared
  `mirror-verify` workflow gates this job.
- Reject present-but-null required fields in the approved-lock validator so a
  nulled `source_digest`, `target_digest`, `ghcr_ref`, `kind`, or `promoted`
  cannot bypass the provenance checks; match digests with `re.fullmatch` so a
  trailing-newline digest cannot pass the format gate; and constrain the YAML
  loader's path to a regular `.yaml`/`.yml` file before opening it (SonarCloud
  S8707).
- Move CI secrets out of `run:` script interpolation into step-level `env:` blocks
  in the mirror workflow, so secret values are no longer expanded directly into
  shell command lines.
- Validate the `GITHUB_OUTPUT` path in `build_matrix.py` (absolute path with an
  existing parent directory) before appending to it, falling back to stdout
  otherwise, to prevent writes being redirected to an unexpected location.
- Scope the Scorecard workflow's top-level permissions to `contents: read` instead
  of `read-all`.
- Verify the crane tarball against a pinned `CRANE_SHA256` in both mirror jobs
  before extraction, eliminating trust in the fetched `checksums.txt` path.
- Add `--fail` to `curl` in crane install steps so HTTP errors surface rather than
  producing a silently corrupted download.
- Use `--password-stdin` for all three `crane auth login` calls in the mirror
  pipeline, keeping credentials out of process argument lists.
- Pin `anchore/syft` by digest (`sha256:${SYFT_SHA256}`) in both mirror jobs
  instead of a tag-only reference.
- Pin `pyyaml==6.0.3` in the mirror `prepare` job.

### Fixed

- `build_matrix.py`: `build_include()` now catches `KeyError` and prints a
  diagnostic naming the image id and missing field before exiting 1, replacing
  a bare traceback on structurally incomplete catalog entries.
- `publish-approved-image.yml`: emit a `::notice::` annotation and step summary
  row when `SNYK_TOKEN` is absent so the scan skip is visible rather than silent.

### Changed

- Docs: update `CLAUDE.md` to reflect A2 as complete and A3 as partially complete,
  and expand the key-files table to cover all scripts and workflows added in A2/A3.

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
