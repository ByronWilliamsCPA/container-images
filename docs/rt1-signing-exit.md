# RT-1: mirror signing window - status, exit plan, review date

**Status as of 2026-08-25**

| Path | Upstream identity verified? | Our signature + SBOM attestation? |
| --- | --- | --- |
| `supply-chain-mirror.yml` (distroless-static) | **yes**, fail-closed | **yes** |
| `mirror-hardened-images.yml` (all 33 catalog entries) | no | **no** (`MIRROR_SIGNING_ENABLED=false`) |

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

`distroless-static` is therefore the first image in this org published with a
verified upstream identity, our own signature, and an SBOM attestation.

## Per-entry readiness

Measured 2026-08-25 with Trivy 0.70.0 against the live GHCR content of every
catalog entry. "fixable" counts findings that have a fixed version available
upstream - the ones the promotion gate acts on.

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

`ghcr.io/byronwilliamscpa/distroless-static:latest` is the exception - it is
published by the `supply-chain-mirror` path and is signed and attested.

Pin by digest regardless. The mirror's promotion gate means a mutable tag now
stops advancing when the scan finds something actionable, but a tag is still a
tag: it can move on any run that passes.
