#!/usr/bin/env bash
# Accuracy regression test on real-world manifests.
#
# Downloads the pinned manifests in corpus.txt, scans each with the baseline
# profile, and compares every finding (rule, severity, resource, message)
# with the reviewed golden file. A difference is either a regression or an
# improvement: review it, then run with --update and commit the new golden
# files together with the change that caused them.
#
# Every downloaded file is checked against corpus.sha256, so a changed
# upstream file (a moved tag, a re-uploaded release asset) is reported as
# such rather than as a change in Hardex's findings. --update also rewrites
# the checksums of files that are new to corpus.txt.
set -euo pipefail
cd "$(dirname "$0")"
HARDEX="${HARDEX:-../../bin/hardex}"
update=false
[ "${1:-}" = --update ] && update=true
cache="${CORPUS_CACHE:-$(mktemp -d)}"
mkdir -p golden "$cache"
touch corpus.sha256
status=0
while read -r name urls; do
  case "$name" in ''|'#'*) continue ;; esac
  dir="$cache/$name"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir.tmp"
    i=0
    for u in $urls; do
      i=$((i+1))
      curl -sSfL --retry 5 --retry-all-errors --retry-delay 3 -o "$dir.tmp/$i.yaml" "$u"
    done
    mv "$dir.tmp" "$dir"
  fi
  for f in "$dir"/*.yaml; do
    key="$name/$(basename "$f")"
    sum="$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | cut -d' ' -f1)"
    want="$(awk -v k="$key" '$2 == k {print $1}' corpus.sha256)"
    if [ -z "$want" ] && $update; then
      echo "$sum  $key" >> corpus.sha256
    elif [ "$sum" != "$want" ]; then
      echo "UPSTREAM CHANGED: $key (sha256 $sum, pinned ${want:-none}); the downloaded file differs from the reviewed one"
      status=1
      continue 2
    fi
  done
  out="$cache/$name.txt"
  "$HARDEX" scan --profile baseline --fail-on none --format json "$dir" \
    | jq -r '.findings[] | "\(.ruleId) \(.severity) \(.resource.kind) \(.resource.namespace // "-")/\(.resource.name)\(if .resource.container then "[" + .resource.container + "]" else "" end) | \(.message)"' \
    | LC_ALL=C sort > "$out"
  if $update; then
    cp "$out" "golden/$name.txt"
    echo "updated golden/$name.txt ($(wc -l < "$out") findings)"
  elif ! diff -u "golden/$name.txt" "$out" > "$cache/$name.diff"; then
    echo "CHANGED: $name"
    cat "$cache/$name.diff"
    status=1
  else
    echo "ok: $name ($(wc -l < "$out") findings)"
  fi
done < corpus.txt
exit $status
