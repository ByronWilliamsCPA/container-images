# Container Images Mirror

Public mirror of hardened container images from Docker Hardened Images (DHI)
and Google Distroless, hosted on GitHub Container Registry (GHCR).

All images are publicly pullable with no authentication required.

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

## Usage

No authentication required:

```bash
docker pull ghcr.io/byronwilliamscpa/dhi-postgres:16-debian13
docker pull ghcr.io/byronwilliamscpa/distroless-python3:latest
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

Every DHI image in this mirror carries:

- SLSA Level 3 provenance (from DHI upstream)
- AMD64; ARM64 planned

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
> **Exception:** `distroless-static:latest` is published by the
> `supply-chain-mirror` path, which verifies the upstream distroless signer
> fail-closed before promoting. It is signed and SBOM-attested.
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
