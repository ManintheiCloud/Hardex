# Image digests and signatures

Mutable tags (HX-WL-011) and missing digests (HX-WL-012) are found offline by every scan. `hardex images` goes further: it contacts the registries to resolve what each tag points to right now, and verifies cosign signatures against keys you trust.

```sh
hardex images ./k8s                                    # resolve tags to digests
hardex images --cluster                                # every image running in the cluster
hardex images --cluster --key cosign.pub --require-signature   # gate: every image signed by our key
hardex images ./k8s --require-digest                   # gate: no mutable references
hardex images ./k8s --offline                          # no network: just classify references
```

For every tag-referenced image Hardex prints the `image@sha256:…` reference to pin, so pinning is a copy-paste.

## What is verified

- **Key-based cosign signatures** (`cosign sign --key …`), stored in the registry next to the image (`sha256-<digest>.sig`). An image is reported **verified** only if a signature over a payload naming *that exact digest* verifies with one of the `--key` public keys (ECDSA, Ed25519 or RSA, PEM). A valid signature for another digest never verifies an image.
- **Registry integrity**: every manifest and blob fetched by digest is re-hashed and compared with the digest requested, so a compromised registry or proxy cannot substitute content.

Statuses: `verified`, `unsigned` (no key-based signature found), `invalid` (signatures exist but none verify for this digest with your keys), `error` (the check could not complete — treated as a failure by `--require-signature`, exit 3).

## What is not verified here

**Keyless** signatures (Fulcio certificates and the Rekor transparency log) and the newer **Sigstore bundle format** stored as OCI referrers require the Sigstore trust root and transparency-log verification; Hardex does not implement these and reports such images as `unsigned` rather than guessing. Verify them with cosign, and enforce them at admission with a Sigstore policy controller:

```sh
cosign verify ghcr.io/org/app@sha256:… \
  --certificate-identity-regexp '^https://github.com/org/app/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Registry access

- HTTPS only; anonymous access works for public images. For private registries Hardex reads basic credentials from `~/.docker/config.json` (or `$DOCKER_CONFIG`) — run `docker login` first. Credential helpers are not supported.
- Token services must be HTTPS; responses are size-limited.
- Up to eight registry requests run in parallel.

Hardex's own images are signed keylessly; see [verifying-releases.md](verifying-releases.md).
