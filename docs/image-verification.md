# Image digests and signatures

Mutable tags (HX-WL-011) and missing digests (HX-WL-012) are found offline by every scan. `hardex images` goes further: it contacts the registries to resolve what each tag points to right now, verifies signatures — cosign keys you trust, or keyless Sigstore signatures from an identity you name — and looks up known vulnerabilities from each image's SBOM.

```sh
hardex images ./k8s                                    # resolve tags to digests
hardex images --cluster                                # every image running in the cluster
hardex images --cluster --key cosign.pub --require-signature   # gate: every image signed by our key
hardex images ./k8s --require-digest                   # gate: no mutable references
hardex images ./k8s --offline                          # no network: just classify references

# keyless: every image signed by our release workflow, verified offline against Sigstore
hardex images --cluster --require-signature \
  --certificate-identity-regexp '^https://github\.com/org/app/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

hardex images ./k8s --vulns                            # known vulnerabilities (OSV) from SBOM attestations
hardex images ./k8s --vulns --fail-on-vulns            # gate: no known vulnerabilities, and an SBOM present
```

For every tag-referenced image Hardex prints the `image@sha256:…` reference to pin, so pinning is a copy-paste.

## What is verified

- **Key-based cosign signatures** (`cosign sign --key …`), stored in the registry next to the image (`sha256-<digest>.sig`). An image is reported **verified** only if a signature over a payload naming *that exact digest* verifies with one of the `--key` public keys (ECDSA, Ed25519 or RSA, PEM). A valid signature for another digest never verifies an image.
- **Keyless Sigstore signatures** (`--certificate-identity[-regexp]` with `--certificate-oidc-issuer[-regexp]`, cosign's flag names). Hardex finds Sigstore bundles attached to the digest as OCI referrers (cosign v3, GitHub artifact attestations; the referrers API with the `sha256-<digest>` tag fallback) and cosign's legacy keyless `.sig` format, and verifies each **completely offline** against the Sigstore trusted root:
  - the Fulcio certificate chains to a trusted CA and was valid at the signing time;
  - it carries a valid SCT from a trusted certificate-transparency log;
  - the signature verifies over the image digest (message signatures), or the DSSE envelope verifies and its in-toto statement names the image digest as a subject (attestations);
  - the Rekor entry matches the signature, certificate and digest, and is proven by a signed entry timestamp and/or an inclusion proof against a checkpoint signed by the log;
  - the signing time comes from the log's signed integration time or an RFC 3161 timestamp from a trusted authority;
  - the certificate's identity and OIDC issuer match what you required. There is no way to verify keyless signatures *without* an identity: "signed by someone" proves nothing.

  The trusted root of the Sigstore public-good instance is embedded in Hardex (from [sigstore/root-signing](https://github.com/sigstore/root-signing), checked against its TUF targets metadata at release time). When Sigstore rotates keys, upgrade Hardex or pass a current `trusted_root.json` with `--trusted-root`. Rekor v1 entries (`hashedrekord`, `dsse`, `intoto`) and Rekor v2 entries (tile-based logs: the entry is recomputed from the bundle and proven against a signed checkpoint, with the signing time from a timestamp authority) are both supported. The verifier passes every certificate-based case of the Sigstore project's client [conformance suite](https://github.com/sigstore/sigstore-conformance), which runs in Hardex's tests.
- **Registry integrity**: every manifest and blob fetched by digest is re-hashed and compared with the digest requested, so a compromised registry or proxy cannot substitute content.

Statuses: `verified` (with the key, or the signer identity and predicate type), `unsigned` (no signature of the requested kind found), `invalid` (signatures exist but none verify for this digest and policy; the reasons are listed), `error` (the check could not complete — treated as a failure by `--require-signature`, exit 3). With both `--key` and a keyless identity, either one verifying is enough.

To verify a file rather than an image — for example a Hardex release — use `hardex verify-blob` (see [verifying-releases.md](verifying-releases.md)).

## Vulnerabilities

`--vulns` reads the SBOM attestations that `docker buildx build --sbom=true` attaches to an image index (SPDX or CycloneDX in-toto statements), and looks every versioned package URL up in [OSV](https://osv.dev) in batches. For each image it reports the affected packages and OSV IDs, or `unknown (no SBOM attestation)` — never "clean" when there was nothing to check. `--fail-on-vulns` exits 1 if any image has known vulnerabilities or no SBOM, and 3 if a lookup failed.

- The SBOM is fetched through the image index by digest, so it is integrity-protected by the same digest you pinned and verified; BuildKit itself does not sign SBOMs.
- Only package names and versions (package URLs) are sent to the OSV API — no image names or cluster data. `--osv-url` points at a mirror.
- OSV lists vulnerabilities by package version; whether vulnerable code is reachable in the image is not analysed. Severity is not shown; follow the OSV IDs.

## Registry access

- HTTPS only; anonymous access works for public images. For private registries Hardex reads basic credentials from `~/.docker/config.json` (or `$DOCKER_CONFIG`) — run `docker login` first. Credential helpers are not supported.
- Token services must be HTTPS; responses are size-limited.
- Up to eight registry requests run in parallel.

Hardex's own images are signed keylessly and carry SBOM attestations; see [verifying-releases.md](verifying-releases.md).
