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
- CycloneDX SBOM attestation via cosign keyless signing
- Multi-arch manifests (AMD64 and ARM64 under the same tag)

## Requesting a new image

Open a pull request adding an entry to the matrix in
`.github/workflows/mirror-hardened-images.yml`.

## License

MIT. See [LICENSE](LICENSE).
