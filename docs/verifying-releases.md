# Verifying Hardex releases

Every release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) from a version tag, with no long-lived signing keys:

| Artifact | Integrity | Authenticity / provenance |
|---|---|---|
| Binaries (`hardex_<version>_<os>_<arch>.tar.gz` / `.zip`) | `SHA256SUMS` | Keyless Sigstore signature on `SHA256SUMS` (`SHA256SUMS.sigstore.json`); GitHub build-provenance attestation (SLSA) per archive |
| SBOM (`hardex.spdx.json`) | `SHA256SUMS` | Build-provenance attestation |
| Container image `ghcr.io/manintheicloud/hardex:<version>` (linux/amd64, linux/arm64) | content digest | Keyless cosign signature; build-provenance attestation; BuildKit SBOM and provenance |

## Binaries

```sh
# 1. Checksums are signed by the release workflow of this repository
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ManintheiCloud/Hardex/\.github/workflows/release\.yml@refs/(tags/v|heads/main)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Your download matches the signed checksums
sha256sum --ignore-missing -c SHA256SUMS

# 3. (optional) Provenance: built from this repository by GitHub Actions
gh attestation verify hardex_0.4.0_linux_amd64.tar.gz --repo ManintheiCloud/Hardex
```

## Container image

```sh
cosign verify ghcr.io/manintheicloud/hardex:0.4.0 \
  --certificate-identity-regexp '^https://github.com/ManintheiCloud/Hardex/\.github/workflows/release\.yml@refs/(tags/v|heads/main)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/manintheicloud/hardex:0.4.0 --repo ManintheiCloud/Hardex
```

Deploy by digest: take the digest printed by `cosign verify` (or `hardex images deploy/`) and replace the tag in the `deploy/` manifests.
