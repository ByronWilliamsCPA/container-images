# Security Policy

This repository mirrors hardened container images from upstream registries
(dhi.io, gcr.io) to GHCR for use by other homelab projects. Because downstream
workloads run these images directly, supply-chain integrity is the primary
security concern.

## Supported Versions

The latest images mirrored to the `main` branch are supported. This repository
does not publish versioned library releases; each mirror run produces images
pinned to the upstream digest at the time of mirroring.

## Reporting a Vulnerability

To report a vulnerability privately, use GitHub's
[Private Vulnerability Reporting](https://github.com/ByronWilliamsCPA/container-images/security/advisories/new)
feature. Do not open a public issue for security matters.

We commit to acknowledging all vulnerability reports within 14 days of
submission.

## Verifying Mirrored Images

All images mirrored by this repository are signed with cosign using keyless
(Sigstore) signatures bound to the GitHub Actions OIDC identity.

**Verify a cosign signature:**

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/ByronWilliamsCPA/container-images" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/byronwilliamscpa/<image>:<tag>
```

**Verify a CycloneDX SBOM attestation:**

```bash
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "https://github.com/ByronWilliamsCPA/container-images" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/byronwilliamscpa/<image>:<tag>
```

Images are copied by digest (not by tag) from upstream using `crane cp` with a
digest assertion. This prevents tag-swap substitution attacks by ensuring the
content hash is verified before the image is pushed to GHCR.

## Security Surface

Primary attack vectors for this repository:

- **Upstream registry compromise:** a malicious image pushed to dhi.io or gcr.io
  before the mirror job runs. Mitigation: crane copies by digest with assertion;
  cosign signs the result; SBOM is attested for post-mirror review.
- **Credential theft:** leakage of the GHCR push token or the GitHub Actions
  OIDC token. Mitigation: tokens are scoped to this workflow only, harden-runner
  egress auditing is active, and no long-lived credentials are stored as secrets.
- **Digest tampering:** a man-in-the-middle or registry response altering the
  image content after the digest is recorded. Mitigation: crane assertions and
  cosign verification tie every published image to its upstream digest.
