# Sigstore conformance test vectors

Copied verbatim from `test/assets/bundle-verify` of
[sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
at commit 43321d80f52958efa584c6c975716150db62180b (2026-10-19),
licensed under the Apache License 2.0.

`conformance_test.go` runs every case: directories ending in `_fail` must be
rejected, all others must verify. Cases using a managed key (`key.pub`)
instead of a certificate are out of scope for this package (key-based
signatures are verified by `core/imagesig`) and are skipped.
