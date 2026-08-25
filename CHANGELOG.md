# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- The mirror's Trivy scan now gates promotion instead of trailing it
  (RT-4). `mirror-hardened-images.yml` resolves the upstream digest, scans that
  digest, and runs `crane copy` only if the scan passes. Previously the copy ran
  first, so a failing scan reported failure while the public mutable tag had
  already advanced: the run read as a gate and behaved as a report. Scanning the
  upstream digest rather than a staging tag keeps the copy content-addressed, so
  no unvetted bytes reach GHCR and there is nothing to stage or clean up.
- The mirror gate blocks only on findings that have a fix available upstream
  (`scanner_policy.trivy.ignore_unfixed` in `catalog/policies.yaml`). This mirror
  is transport and cannot patch a package, so an unfixable finding is
  unactionable here, while a fixable one means upstream shipped a build that lags
  an available patch. Measured over the live catalog on 2026-08-25, this leaves
  22 of 33 images clean and 11 blocked on genuinely actionable findings, ending a
  streak in which every scheduled run since 2026-06-28 failed and a new CRITICAL
  would have been indistinguishable from the noise. Unfixed findings are still
  scanned and still uploaded as SARIF.
- Both promotion paths now read their thresholds, ignore-unfixed flag and CVE
  exceptions from `catalog/policies.yaml` via `scripts/load_scanner_policy.py`.
  `publish-approved-image.yml` also honours `ignore_unfixed`, so the unattended
  mirror and the human-approved promotion cannot apply different gates to the
  same catalog entry.

### Fixed

- Give each mirror matrix leg its own SARIF category
  (`trivy-${{ matrix.id }}`). Every leg previously uploaded to the same default
  category, so the 33 legs overwrote each other's alerts and only the
  last-finishing job's findings survived in the Security tab.
- Surface the blocking CVEs in the mirror job log and step summary. The gate now
  runs in table format, so a failed run names the packages and fixed versions
  instead of leaving the reason visible only in the Security tab.
- Emit a `::warning::` annotation for each exception dropped as expired or
  malformed. Expiry was already fail-safe (a lapsed exception reverts to
  blocking) but invisible, so a run would go red on a CVE someone believed was
  still covered.

### Added

- `docs/rt1-signing-exit.md`: the RT-1 exit plan. Per-entry migration readiness
  for all 33 catalog entries, the three blockers holding the DHI half of the
  catalog on the legacy path, the sequence for retiring
  `mirror-hardened-images.yml`, and a **2026-11-24 review date** so downstream
  consumers can plan around unsigned images rather than discover them.
- A3 approved-lock provenance validator (`scripts/verify_approved_lock.py`),
  wired into the required Validate Catalog Schema gate. It verifies every
  promotion entry in `catalog/approved-lock.yaml`: schema conformance, the
  `source_digest == target_digest` provenance invariant, digest format, and a
  catalog cross-reference of each promoted `id` and `ghcr_ref`.

### Security

- Configure fail-closed upstream-identity verification on the distroless mirror
  path. `supply-chain-mirror.yml` now sets `require_upstream_signature: true`
  with the distroless signer pinned (`keyless@distroless.iam.gserviceaccount.com`
  via `https://accounts.google.com`, confirmed 2026-08-25 against
  `static-debian12`, `python3-debian12` and `nodejs20-debian12`; both the index
  and per-platform digests are signed, which matters because `mirror-verify`
  verifies a platform digest). This is configuration, not yet a published
  outcome: RT-1 closes for this path only after a successful run on `main`.
  Nothing in the GHCR namespace is signed today, `distroless-static:latest`
  included. The DHI half of the catalog stays in the interim window: `dhi.io`
  needs entitlement credentials to read a signature, so the DHI signer identity
  is still unknown.
- Refuse a `supply-chain-mirror` run that would publish without signing.
  `promote-core` gates cosign signing, SBOM attestation, build provenance and
  the lock update on `github.ref == 'refs/heads/main'`, and this caller is
  `workflow_dispatch`-only, so a dispatch from a branch published to GHCR and
  skipped all four while still reporting success. Run 28477177390 (2026-06-30)
  did exactly that: green, dispatched from a feature branch, `distroless-static`
  published unsigned, `approved-lock.yaml` left empty, and the state believed
  good for two months. A `preflight` job now fails such a dispatch unless
  `allow_unsigned_dry_run` is set, and a `verify-published` job asserts against
  the **registry** that a signature and CycloneDX attestation exist for the
  promoted digest, so a green run can no longer stand in for a signed artifact.
- Stop minting cosign signatures and SBOM attestations in the live mirror until
  upstream-identity verification exists (RT-1 interim, ADR-012). A
  `MIRROR_SIGNING_ENABLED` kill-switch (default `false`) gates all four Sign/Attest
  steps in `mirror-hardened-images.yml`, while `crane copy`, digest-equality assert,
  Trivy scan, and SBOM generation still run. Signing previously minted this org's
  keyless identity over unverified upstream bytes (trust laundering); disabling it
  removes false trust, not a working dependency. Re-enable once the shared
  `mirror-verify` workflow gates this job.
- Add upstream registry allowlist (`dhi.io`, `gcr.io`) so any unlisted or
  null registry is rejected at catalog validation time (RT-2).
- Validate `upstream.name`, `upstream.tag`, `ghcr.name`, and `ghcr.tag` against
  compiled regex patterns; drop the `is not None` guards that previously allowed
  YAML null values to bypass shape checks (RT-7).
- Switch `_matches()` to `re.fullmatch` so a trailing-newline in a field value
  cannot bypass tag, name, or digest pattern gates.
- Require an explicit `sha256:` digest pin for any entry whose `upstream.tag` is a
  mutable label (`latest`, `stable`, `edge`, etc.) so the mirror copies exactly
  the bytes vetted at review time and cannot drift (RT-6).
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
