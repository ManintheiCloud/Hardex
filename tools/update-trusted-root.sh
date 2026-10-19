#!/usr/bin/env bash
# Checks (and with --write, updates) the Sigstore public-good trusted root
# embedded in core/sigstore against github.com/sigstore/root-signing.
#
# The candidate file must match the sha256 recorded for it in the TUF
# targets metadata of the same repository. Exit status: 0 up to date (or
# updated with --write), 1 out of date, 2 error.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EMBEDDED="$ROOT/core/sigstore/trusted_root.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone -q --depth 1 https://github.com/sigstore/root-signing.git "$tmp/rs"
candidate="$tmp/rs/targets/trusted_root.json"
want="$(jq -r '.signed.targets["trusted_root.json"].hashes.sha256' "$tmp/rs/metadata/targets.json")"
have="$(sha256sum "$candidate" | cut -d' ' -f1)"
if [ "$want" != "$have" ]; then
  echo "root-signing: trusted_root.json ($have) does not match its TUF targets entry ($want)" >&2
  exit 2
fi
expires="$(jq -r '.signed.expires' "$tmp/rs/metadata/targets.json")"
commit="$(git -C "$tmp/rs" rev-parse HEAD)"
current="$(sha256sum "$EMBEDDED" | cut -d' ' -f1)"
if [ "$current" = "$have" ]; then
  echo "embedded trusted root is current (sha256 $have, root-signing $commit, targets expire $expires)"
  exit 0
fi
echo "embedded trusted root is OUT OF DATE: have $current, root-signing $commit has $have"
if [ "${1:-}" = "--write" ]; then
  cp "$candidate" "$EMBEDDED"
  echo "updated $EMBEDDED; run go test ./core/sigstore/ and commit"
  exit 0
fi
exit 1
