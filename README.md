# Container Images Mirror

Public mirror of hardened container images from Docker Hardened Images (DHI)
and Google Distroless, plus a small set of third-party vendor application images
from Docker Hub, hosted on GitHub Container Registry (GHCR).

All images are publicly pullable with no authentication required.

Three source tiers, three prefixes, three different promises. Do not read a
`vendor-*` image as hardened because it sits in the same namespace as a `dhi-*`
one; see [Hardened-base mirrors versus vendor mirrors](#hardened-base-mirrors-versus-vendor-mirrors).

## Available images

### Docker Hardened Images (`dhi-*`)

Sourced from `dhi.io`. Approximately 95% CVE reduction versus standard Docker Hub
equivalents. All carry CIS compliance hardening; many carry FIPS and STIG as well.

| Image | Tag | Use for |
| --- | --- | --- |
| `ghcr.io/byronwilliamscpa/dhi-postgres` | `16-debian13` | PostgreSQL 16 |
| `ghcr.io/byronwilliamscpa/dhi-postgres` | `14-debian13` | PostgreSQL 14 |
| `ghcr.io/byronwilliamscpa/dhi-redis` | `7-debian13` | Redis 7 |
| `ghcr.io/byronwilliamscpa/dhi-python` | `3.12-debian13` | Python 3.12 base |
| `ghcr.io/byronwilliamscpa/dhi-python` | `3.11-debian13` | Python 3.11 base |
| `ghcr.io/byronwilliamscpa/dhi-node` | `24-debian13` | Node.js 24 |
| `ghcr.io/byronwilliamscpa/dhi-node` | `22-debian13` | Node.js 22 |
| `ghcr.io/byronwilliamscpa/dhi-nginx` | `1.26-debian13` | nginx 1.26 stable (ELS) |
| `ghcr.io/byronwilliamscpa/dhi-nginx` | `1.27-debian12` | nginx 1.27 mainline |
| `ghcr.io/byronwilliamscpa/dhi-traefik` | `3.6-debian13` | Traefik 3.6 |
| `ghcr.io/byronwilliamscpa/dhi-traefik` | `3.5-debian13` | Traefik 3.5 |
| `ghcr.io/byronwilliamscpa/dhi-grafana` | `12.3-debian13` | Grafana 12.3 |
| `ghcr.io/byronwilliamscpa/dhi-grafana` | `11.6-debian13` | Grafana 11.6 |
| `ghcr.io/byronwilliamscpa/dhi-prometheus` | `3.8-debian13` | Prometheus 3.8 |
| `ghcr.io/byronwilliamscpa/dhi-prometheus` | `3.5-debian13` | Prometheus 3.5 (LTS) |
| `ghcr.io/byronwilliamscpa/dhi-loki` | `3.6-debian13` | Grafana Loki 3.6 |
| `ghcr.io/byronwilliamscpa/dhi-loki` | `2.9-debian13` | Grafana Loki 2.9 |
| `ghcr.io/byronwilliamscpa/dhi-promtail` | `3.5-debian13` | Promtail 3.5 |
| `ghcr.io/byronwilliamscpa/dhi-alloy` | `1-debian13` | Grafana Alloy 1.x |
| `ghcr.io/byronwilliamscpa/dhi-node-exporter` | `1-debian13` | Prometheus Node Exporter |
| `ghcr.io/byronwilliamscpa/dhi-postgres-exporter` | `0-debian13` | PostgreSQL metrics exporter |
| `ghcr.io/byronwilliamscpa/dhi-redis-exporter` | `1-debian13` | Redis metrics exporter |
| `ghcr.io/byronwilliamscpa/dhi-uptime-kuma` | `1-debian13` | Uptime Kuma 1.x |
| `ghcr.io/byronwilliamscpa/dhi-uv` | `0-debian13` | uv Python package manager |

### Distroless images (`distroless-*`)

Sourced from `gcr.io/distroless`. Minimal runtime images with no shell or package
manager. Best used as the final stage in multi-stage builds.

| Image | Tag | Use for |
| --- | --- | --- |
| `ghcr.io/byronwilliamscpa/distroless-python3` | `latest` | Python 3 production runtime |
| `ghcr.io/byronwilliamscpa/distroless-nodejs20` | `latest` | Node.js 20 production runtime |
| `ghcr.io/byronwilliamscpa/distroless-static` | `latest` | Static binaries (Go, Rust) |

### Vendor images (`vendor-*`)

Third-party application images sourced from Docker Hub (`docker.io`), mirrored
for the CYO Supabase self-host stack (ADR-032). **These are transport copies of
upstream, not hardened images.** They are pinned by digest in the catalog, scanned
by the same gate as every other image, and otherwise published as upstream built
them. Each tag is the upstream tag. Like every image in this mirror, only
`linux/amd64` is published: it is the platform the scan gate inspects, so no
architecture reaches GHCR unscanned. Upstream also builds `linux/arm64`; that is
not mirrored.

| Image | Tag | Upstream |
| --- | --- | --- |
| `ghcr.io/byronwilliamscpa/vendor-supabase-studio` | `2026.10.12-sha-3699278` | `supabase/studio` |
| `ghcr.io/byronwilliamscpa/vendor-envoy` | `v1.39.4` | `envoyproxy/envoy` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-gotrue` | `v2.197.0` | `supabase/gotrue` |
| `ghcr.io/byronwilliamscpa/vendor-postgrest` | `v14.18` | `postgrest/postgrest` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-realtime` | `v2.143.3` | `supabase/realtime` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-storage-api` | `v1.81.0` | `supabase/storage-api` |
| `ghcr.io/byronwilliamscpa/vendor-imgproxy` | `v3.31.4` | `darthsim/imgproxy` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-postgres-meta` | `v0.100.0` | `supabase/postgres-meta` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-edge-runtime` | `v1.77.4` | `supabase/edge-runtime` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-postgres` | `17.6.1.136` | `supabase/postgres` |
| `ghcr.io/byronwilliamscpa/vendor-supabase-supavisor` | `2.9.13` | `supabase/supavisor` |

## Usage

No authentication required:

```bash
docker pull ghcr.io/byronwilliamscpa/dhi-postgres:16-debian13
docker pull ghcr.io/byronwilliamscpa/distroless-python3:latest
docker pull ghcr.io/byronwilliamscpa/vendor-supabase-gotrue:v2.197.0
```

In a Dockerfile:

```dockerfile
FROM ghcr.io/byronwilliamscpa/dhi-python:3.12-debian13 AS build
# ... build steps ...

FROM ghcr.io/byronwilliamscpa/distroless-python3:latest
COPY --from=build /app /app
```

## Update schedule

Images are re-mirrored every Sunday at 2 AM UTC, and on every push to this
repository. Manual trigger is available via GitHub Actions workflow dispatch.

## Security

Every DHI image in this mirror carries (vendor and distroless images do not):

- SLSA Level 3 provenance (from DHI upstream)
- AMD64; ARM64 planned

### Hardened-base mirrors versus vendor mirrors

The catalog's `source_tier` says what a mirrored image is, and the validator
enforces a different rule set per tier (ADR-032).

| Tier | Prefix | Upstream | What it means | Pin |
| --- | --- | --- | --- | --- |
| `primary` | `dhi-*` | `dhi.io` | Docker Hardened Images base: minimal, CIS-hardened, upstream-maintained | tag, resolved per run |
| `distroless` | `distroless-*` | `gcr.io` | Google Distroless: no shell, no package manager | tag, optional digest |
| `vendor` | `vendor-*` | `docker.io` | A third party's application image, copied as published | immutable tag **and** required digest |

- **RT-2, per-tier registries.** Each tier may use exactly one registry. A
  `vendor` entry cannot point at `dhi.io`, and a `primary` entry cannot point at
  `docker.io`, so an application image cannot be passed off as a hardened base by
  picking the other tier's registry.
- **RT-6, digest pin is mandatory for vendor.** A floating tag is refused
  outright for the tier, and `upstream.digest` is required whatever the tag says.
  The pin is the upstream multi-arch index digest. The mirror resolves the
  `linux/amd64` manifest from that index, scans it, copies it by digest
  (`crane copy SRC@DIGEST TGT`) and asserts the target digest matches. If upstream re-pushes a tag, the mirror keeps serving
  the reviewed digest and the run warns, rather than silently following the tag.
- **RT-4, same scan gate.** Vendor images go through the same Trivy gate as the
  other tiers, before the copy, with thresholds from `catalog/policies.yaml`.
  There are no vendor-specific ignores. A vendor image with a fixable
  CRITICAL or HIGH finding is held back like any other.
- **RT-1, no upstream signature check.** Docker Hub vendor images are mostly
  unsigned and no signer has been confirmed for any of them. The run summary says
  "upstream signature NOT verified" for every vendor leg. Vendor signing has its
  own switch (`MIRROR_VENDOR_SIGNING_ENABLED`, currently `false`) in addition to
  `MIRROR_SIGNING_ENABLED`, so lifting RT-1 for the other tiers cannot sign
  unverified vendor bytes.

A `vendor-*` image carries upstream's CVE posture and upstream's base image. The
mirror contributes a digest pin, a scan gate and an SBOM, not hardening.

### Scanning gates promotion

The mirror resolves the upstream digest, scans **that digest** with Trivy, and
copies to GHCR only if the scan passes. A failing run therefore leaves the public
tag pointing at its previous digest rather than advancing it, and no unvetted
bytes are ever pushed.

The gate blocks on CRITICAL and HIGH findings **that have a fix available
upstream**. This mirror is transport - `crane copy` moves upstream bytes
unchanged and cannot patch a package - so a finding with no fix anywhere is not
something the pipeline can act on. A finding that does have a fix means upstream
shipped a build that lags an available patch, and holding the tag is the right
response. Unfixed findings are still scanned and still uploaded to the Security
tab; they just do not gate.

Thresholds, that ignore-unfixed rule, and time-boxed per-CVE exceptions all live
in [`catalog/policies.yaml`](catalog/policies.yaml). Exceptions require a
justification, a ticket, and an expiry date, and revert to blocking the moment
they lapse.

The Trivy gate also fails on **secrets** (for example a bundled private key), and
`--ignore-unfixed` does not apply to them. A `secret_exceptions` entry names one
rule and one exact absolute path, never a glob, and carries the same expiry and
ticket requirements. It applies to the vendor tier only.

**Pin by digest.** A gated tag stops advancing on a bad scan, but it is still a
mutable tag and moves on any run that passes.

### Signing status

> **Mirror signing is disabled for the images in the tables above (RT-1 interim,
> ADR-012).** This mirror copies a mutable upstream tag, so signing and attesting
> here would mint this org's keyless identity over bytes whose upstream signer was
> never verified. CycloneDX SBOM attestation and cosign keyless signing are
> therefore OFF (`MIRROR_SIGNING_ENABLED=false`). Images mirrored during this
> window are unsigned: there is no `.sig` tag and no OCI referrer, and a
> `cosign verify` against this org's identity will fail. That is expected.
>
> **This includes `distroless-static:latest`.** The `supply-chain-mirror` path
> that publishes it is now configured to verify the upstream distroless signer
> fail-closed and to sign and attest, but it has not yet run on `main` under
> that configuration, so the digest currently on that tag is unsigned too.
> Verified against the registry on 2026-08-25: `cosign verify` reports
> `no signatures found` and the referrers API returns `MANIFEST_UNKNOWN`.
> Treat the whole namespace as unsigned until `docs/rt1-signing-exit.md` says
> otherwise, and confirm by querying the registry rather than by reading a
> green workflow run.
>
> **`vendor-*` images are unsigned too, and stay so independently of RT-1.**
> Signing them is behind `MIRROR_VENDOR_SIGNING_ENABLED` (currently `false`) as
> well, because no upstream signer for Docker Hub application images is verified.
>
> **Next review: 2026-11-24.** The migration plan, per-entry readiness, and the
> three blockers are in [`docs/rt1-signing-exit.md`](docs/rt1-signing-exit.md).

## Requesting a new image

Open a pull request that adds an entry to `catalog/images.yaml` following the
schema defined in that file. Validate the catalog locally before pushing:

```bash
python3 scripts/validate_catalog_schema.py
```

## License

MIT. See [LICENSE](LICENSE).
