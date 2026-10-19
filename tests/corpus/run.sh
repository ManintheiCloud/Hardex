#!/usr/bin/env bash
# Accuracy regression test on real-world manifests.
#
# Downloads the pinned manifests in corpus.txt, scans each with the baseline
# profile, and compares every finding (rule, severity, resource, message)
# with the reviewed golden file. A difference is either a regression or an
# improvement: review it, then run with --update and commit the new golden
# files together with the change that caused them.
set -euo pipefail
cd "$(dirname "$0")"
HARDEX="${HARDEX:-../../bin/hardex}"
update=false
[ "${1:-}" = --update ] && update=true
cache="${CORPUS_CACHE:-$(mktemp -d)}"
mkdir -p golden "$cache"
status=0
while read -r name urls; do
  case "$name" in ''|'#'*) continue ;; esac
  dir="$cache/$name"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir.tmp"
    i=0
    for u in $urls; do
      i=$((i+1))
      curl -sSfL --retry 3 -o "$dir.tmp/$i.yaml" "$u"
    done
    mv "$dir.tmp" "$dir"
  fi
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
