#!/usr/bin/env bash
# Installs a Hardex release for the GitHub Action: downloads the archive and
# SHA256SUMS, checks the archive against SHA256SUMS, and (by default) checks
# the archive's SLSA build provenance with `gh attestation verify`, which
# proves it was built by this repository's release workflow.
set -euo pipefail
err() { echo "::error title=hardex action::$*" >&2; }
trap 'err "install failed at line $LINENO: $BASH_COMMAND"' ERR
: "${VERSION:?}"
case "${RUNNER_OS:-$(uname -s)}" in
  Linux) os=linux ;; macOS|Darwin) os=darwin ;; Windows) os=windows ;;
  *) echo "unsupported runner OS ${RUNNER_OS:-}" >&2; exit 2 ;;
esac
case "${RUNNER_ARCH:-$(uname -m)}" in
  X64|x86_64|amd64) arch=amd64 ;; ARM64|arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported runner architecture ${RUNNER_ARCH:-}" >&2; exit 2 ;;
esac
name="hardex_${VERSION}_${os}_${arch}"
ext=tar.gz; [ "$os" = windows ] && ext=zip
dir="${RUNNER_TEMP:-$(mktemp -d)}/hardex-$VERSION"
mkdir -p "$dir"
cd "$dir"
base="https://github.com/ManintheiCloud/Hardex/releases/download/v${VERSION}"
curl -sSfL --retry 3 -o "$name.$ext" "$base/$name.$ext"
curl -sSfL --retry 3 -o SHA256SUMS "$base/SHA256SUMS"
want="$(awk -v f="$name.$ext" '$2 == f || $2 == "*"f {print $1}' SHA256SUMS)"
have="$( (sha256sum "$name.$ext" 2>/dev/null || shasum -a 256 "$name.$ext") | cut -d' ' -f1)"
if [ -z "$want" ] || [ "$want" != "$have" ]; then
  err "checksum mismatch for $name.$ext (want ${want:-<missing>}, have $have)"
  exit 1
fi
if [ "${VERIFY:-true}" = true ]; then
  gh attestation verify "$name.$ext" --repo ManintheiCloud/Hardex \
    --signer-workflow ManintheiCloud/Hardex/.github/workflows/release.yml >/dev/null
  echo "verified build provenance of $name.$ext"
fi
if [ "$ext" = zip ]; then unzip -q -o "$name.$ext"; else tar -xzf "$name.$ext"; fi
bin="$dir/$name/hardex"; [ "$os" = windows ] && bin="$bin.exe"
"$bin" version
echo "path=$bin" >> "${GITHUB_OUTPUT:-/dev/null}"
