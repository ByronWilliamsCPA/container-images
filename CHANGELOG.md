# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

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
