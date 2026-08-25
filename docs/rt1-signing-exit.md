# RT-1: mirror signing window - status, exit plan, review date

**Status as of 2026-08-25**

| Path | Upstream identity verified? | Our signature + SBOM attestation? |
| --- | --- | --- |
| `supply-chain-mirror.yml` (distroless-static) | configured, **not yet run** | **no** - nothing published by this path is signed today |
| `mirror-hardened-images.yml` (all 33 catalog entries) | no | **no** (`MIRROR_SIGNING_ENABLED=false`) |

**Nothing in this org's GHCR namespace is signed as of 2026-08-25.** Verified
against the registry, not against a run's green check:

```
$ crane digest ghcr.io/byronwilliamscpa/distroless-static:latest
sha256:6d635b323e6ab633016668144d38e368e2894bd824500369151573225078ee03
$ cosign verify --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer-regexp '.*' \
    ghcr.io/byronwilliamscpa/distroless-static@sha256:6d635b32...
Error: no signatures found
$ curl .../v2/byronwilliamscpa/distroless-static/referrers/sha256:6d635b32...
{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}
```

`catalog/approved-lock.yaml` is likewise still `promoted: []`.

**Next review: 2026-11-24.** Review earlier if either trigger below fires.

## What RT-1 is

The legacy mirror copies a *mutable* upstream tag. Signing there would mint this
org's keyless identity over bytes whose upstream signer was never verified - a
consumer running `cosign verify` against our identity would read that as "this
org vouches for these bytes", when all we actually did was move them. That is
trust laundering, so PR #26 turned signing off rather than shipping a signature
that means less than it appears to.

The kill-switch is correct and stays on for the legacy path. Closing RT-1 means
*retiring that path*, not flipping the switch.

## What closed today

`supply-chain-mirror.yml` now runs with `require_upstream_signature: true` and a
pinned signer:

```yaml
expected_identity_regexp: '^keyless@distroless\.iam\.gserviceaccount\.com$'
expected_issuer_regexp: '^https://accounts\.google\.com$'
```

Confirmed 2026-08-25 by running `cosign verify` against
`gcr.io/distroless/static-debian12`, `python3-debian12` and `nodejs20-debian12`.
All three are signed by that identity. Both the index digest and the
per-platform digest carry a signature, which matters because `mirror-verify`
resolves a platform digest (`crane digest --platform`) and verifies *that* ref -
an index-only signature would have failed closed on the first real run.

This is configuration, not yet a published outcome. See "Why the green run
lied" below: `distroless-static` is published but **unsigned**, and the run that
published it reported success while signing nothing. `distroless-static` becomes
the first image in this org with a verified upstream identity, our own
signature, and an SBOM attestation only after a successful run of this path
**on `main`** under the new setting - and the way to confirm that is to query
the registry for the `.sig` tag and the referrers API, not to read a green
check.

## Why the green run lied

Every signing and lock step in the shared `supply-chain-promote-core.yml` is
gated on the ref:

```yaml
- name: Sign image with Cosign
  if: inputs.sign && github.ref == 'refs/heads/main'
- name: Attest CycloneDX SBOM
  if: inputs.sign && github.ref == 'refs/heads/main'
- name: GitHub build provenance attestation
  if: inputs.sign && github.ref == 'refs/heads/main'

update-lock:
  if: inputs.write_lock && needs.publish.outputs.promoted == 'true'
      && github.ref == 'refs/heads/main'
```

`supply-chain-mirror.yml` is `workflow_dispatch`-only, so a dispatch from a
feature branch produces a **fully green run that publishes to GHCR and signs
nothing**. The skip is silent: `if:` false is not a warning.

That is exactly what happened. Run
[28477177390](https://github.com/ByronWilliamsCPA/container-images/actions/runs/28477177390)
(2026-06-30) reports `success` and was dispatched from
`feat/supply-chain-bake-distroless-static`. It pushed
`sha256:6d635b32...` to GHCR, skipped all three signing steps and the
`update-lock` job, and the path has not run since. For two months the run list
said "the bake worked".

A pipeline that publishes unsigned and a pipeline that never ran look identical
from the run list. Two guards in `supply-chain-mirror.yml` now close that:

- **`preflight`** fails the run when `sign`/`write_lock` are requested from a
  non-`main` ref, naming the steps that would silently skip. Dispatching from a
  branch to exercise the verify and scan halves is still supported, but it must
  be declared with the `allow_unsigned_dry_run` input - the operator opts into
  an unsigned run rather than discovering one.
- **`verify-published`** runs after promotion on `main` and asserts against the
  **registry** that a signature and an SBOM attestation actually exist for the
  published digest. A green run can no longer mean "signed" unless the artifact
  says so.

Neither guard can be added to the shared reusable workflow from this repo, so
both live in the caller. If the ref gates in `promote-core` are ever relaxed,
`verify-published` still holds, because it checks the artifact rather than the
condition.

## Per-entry readiness

Measured 2026-08-25 with Trivy 0.70.0 against the live GHCR content of every
catalog entry. "fixable" counts findings that have a fixed version available
upstream - the ones the promotion gate acts on.

**Method matters, and this table is reproducible.** Trivy resolves an image
through the local container daemon before the registry, so a stale local copy
carrying an old digest under the same tag yields a different, wrong answer for
what looks like the same command. These numbers were produced in an environment
with no container daemon, so every scan went to the registry. To reproduce, pin
the resolution explicitly - by digest, or by tag with `--image-src remote`:

```
trivy image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
  --image-src remote ghcr.io/byronwilliamscpa/<name>:<tag>
```

A number obtained without one of those is not comparable to this table.

**Why `ignore_unfixed` and not a per-CVE exception list.** This is the
load-bearing justification for the gate policy, so it belongs here rather than
only in `catalog/policies.yaml`. Of the 81 CRITICAL/HIGH findings on
`dhi-python:3.14-debian13`, about 70 are attributed to `linux-libc-dev` -
Debian's kernel *headers* package. It ships no runtime code, a container uses
the host kernel regardless, Trivy attributes every kernel CVE to it, and none of
them carry a fix. Enumerating those as dated exceptions would mean ~79 entries
for one image, each needing renewal, to express a fact that is true of every
Debian-based image in the catalog. `ignore_unfixed` states the actual policy in
one place: a transport mirror gates on what upstream has fixed and it has not
shipped.

| id | tier | CRIT+HIGH | fixable | CRIT | fixable CRIT | glibc |
| --- | --- | --- | --- | --- | --- | --- |
| `dhi-postgres-17` | primary | 15 | 0 | 3 | 0 | yes |
| `dhi-postgres-16` | primary | 15 | 0 | 3 | 0 | yes |
| `dhi-postgres-14` | primary | 15 | 0 | 3 | 0 | yes |
| `dhi-redis-7` | primary | 3 | 0 | 0 | 0 | yes |
| `dhi-python-312` | primary | 81 | 0 | 1 | 0 | yes |
| `dhi-python-312-dev` | primary | 91 | 0 | 4 | 0 | yes |
| `dhi-python-314` | primary | 81 | 0 | 1 | 0 | yes |
| `dhi-python-313` | primary | 81 | 0 | 1 | 0 | yes |
| `dhi-python-311` | primary | 81 | 0 | 1 | 0 | yes |
| `dhi-node-24` | primary | 2 | 0 | 0 | 0 | yes |
| `dhi-node-22` | primary | 2 | 0 | 0 | 0 | yes |
| `dhi-node-22-dev` | primary | 44 | 0 | 12 | 0 | yes |
| `dhi-nginx-127` | primary | 16 | 8 | 4 | 1 | yes |
| `dhi-nginx-126` | primary | 10 | 2 | 2 | 0 | yes |
| `dhi-traefik-37` | primary | 0 | 0 | 0 | 0 | no |
| `dhi-traefik-36` | primary | 0 | 0 | 0 | 0 | no |
| `dhi-traefik-35` | primary | 67 | 60 | 5 | 3 | yes |
| `dhi-uptime-kuma-1` | primary | 3 | 0 | 0 | 0 | yes |
| `dhi-grafana-123` | primary | 3 | 3 | 0 | 0 | yes |
| `dhi-grafana-116` | primary | 20 | 17 | 1 | 1 | yes |
| `dhi-prometheus-38` | primary | 44 | 42 | 2 | 2 | no |
| `dhi-prometheus-35` | primary | 2 | 0 | 0 | 0 | no |
| `dhi-loki-36` | primary | 2 | 2 | 0 | 0 | no |
| `dhi-loki-29` | primary | 1 | 1 | 0 | 0 | no |
| `dhi-promtail-35` | primary | 30 | 28 | 0 | 0 | no |
| `dhi-node-exporter-1` | primary | 0 | 0 | 0 | 0 | no |
| `dhi-postgres-exporter-0` | primary | 0 | 0 | 0 | 0 | no |
| `dhi-redis-exporter-1` | primary | 0 | 0 | 0 | 0 | no |
| `dhi-alloy-1` | primary | 0 | 0 | 0 | 0 | yes |
| `dhi-uv-0` | primary | 0 | 0 | 0 | 0 | yes |
| `distroless-python3` | distroless | 44 | 18 | 2 | 0 | yes |
| `distroless-nodejs20` | distroless | 7 | 6 | 1 | 1 | yes |
| `distroless-static` | distroless | 0 | 0 | 0 | 0 | no |

## Which entries can migrate today

Migrating an entry onto the `supply-chain-mirror` path requires it to clear
**both** gates on that path: `promote-core`'s `grype_fail_on: critical`, and
`mirror-verify`'s fail-closed signer check.

Six DHI entries clear the *scanner* half today - no glibc (so not caught by
CVE-2026-5450, see blocker 1) and zero fixable CRITICAL/HIGH:

- `dhi-traefik-36`, `dhi-traefik-37`
- `dhi-node-exporter-1`, `dhi-postgres-exporter-0`, `dhi-redis-exporter-1`
- `dhi-prometheus-35`

None of them can migrate yet, because all six are `dhi.io` sources and blocker 2
(unknown DHI signer) is unresolved. They are the right first batch the moment it
is, and `dhi-traefik-36`/`-37` are the strongest candidates: both scan
completely clean (zero CRITICAL/HIGH at any fix status) and Traefik is
`criticality: critical`, so it is the entry that benefits most from a real
signature.

`distroless-python3` and `distroless-nodejs20` have a *verifiable* signer (same
distroless identity, already confirmed) but carry 18 and 6 fixable CRITICAL/HIGH
findings respectively, so they fail the scanner half. They migrate when
upstream rebuilds.

## Blockers

### 1. Grype rates glibc CVE-2026-5450 CRITICAL; Debian rates it MEDIUM

22 of 33 catalog entries ship `libc6`. `promote-core` gates on
`grype_fail_on: critical`, and Grype takes NVD severity (9.8 CRITICAL) where
Trivy takes Debian's vendor severity (MEDIUM). There is no trixie backport - the
fix lands in forky/sid - so every glibc-carrying entry fails that gate closed
today, by design.

**What has to be true:** either CVE-2026-5450 reaches `fixed` for Debian trixie
and DHI rebuilds, or `promote-core` grows the same
fix-availability-aware policy the legacy gate now uses (see
`catalog/policies.yaml`, `scanner_policy.trivy.ignore_unfixed`). The second is
the better lever - it is the same argument, and it belongs in the shared core so
both paths agree on what "blocking" means.

**Trigger for early review:** CVE-2026-5450 showing a fixed version for trixie.

### 2. The DHI signer identity is unknown

`dhi.io` requires entitlement credentials to read a manifest, so a signature
cannot be inspected outside a workflow run - `cosign verify` against
`dhi.io/python:3.14-debian13` returns 401 from an unauthenticated client.
`require_upstream_signature: true` with an empty or `.*` identity is refused by
`mirror-verify` (correctly: a wildcard proves only that *some* signature exists),
so the flag cannot be flipped for any DHI entry until the real identity is known.

**What has to be true:** one `workflow_dispatch` run of a `mirror-verify` caller
against a `dhi.io` ref with `require_upstream_signature: false`, with the
`DHI_REGISTRY_*` secrets supplied and the cosign output read from the job log.
That yields the `Subject` and `Issuer` to pin. If DHI turns out not to publish a
cosign signature at all, that is the finding, and the DHI half of the catalog
cannot leave the interim window on this design - it would need a different trust
anchor (DHI's SLSA provenance attestation rather than a cosign signature).

This is the single highest-value next action, and it is cheap: one dispatch run.

**Trigger for early review:** that run completing.

### 3. `supply-chain-mirror.yml` is single-image and dispatch-only

It hardcodes one image and has no catalog-driven matrix, so it cannot replace
`mirror-hardened-images.yml` even for entries that clear both gates.

**What has to be true:** the caller grows a matrix from `scripts/build_matrix.py`
(the same source the legacy mirror uses) plus a per-entry way to carry the
expected signer identity - most naturally a `upstream.signer` block on the
catalog entry, validated by `scripts/validate_catalog_schema.py`, so identity
lives beside the image it belongs to rather than in workflow YAML.

## Sequence

1. Resolve blocker 2 (one dispatch run). **Do this first** - it is the cheapest
   step and it determines whether the rest of the plan is viable at all.
2. Migrate `dhi-traefik-36` and `dhi-traefik-37` as the second bake, mirroring
   how `distroless-static` proved the distroless path.
3. Resolve blocker 3: catalog-carried signer identity + matrix caller.
4. Resolve blocker 1, most likely by moving `ignore_unfixed` into the shared
   promote-core policy.
5. Migrate the remaining entries in readiness order, retire
   `mirror-hardened-images.yml`, and delete `MIRROR_SIGNING_ENABLED` with it.

## For downstream consumers

Until this closes, **every image published by `mirror-hardened-images.yml` is
unsigned and carries no SBOM attestation.** There is no `.sig` tag and no OCI
referrer for these digests; a `cosign verify` against this org's identity will
fail, and that failure is expected, not a compromise indicator.

`ghcr.io/byronwilliamscpa/distroless-static:latest` is published by the
`supply-chain-mirror` path, which is designed to sign and attest - but it has
not yet done so. That digest is unsigned today too. Treat the whole namespace as
unsigned until this document says otherwise.

Pin by digest regardless. The mirror's promotion gate means a mutable tag now
stops advancing when the scan finds something actionable, but a tag is still a
tag: it can move on any run that passes.
