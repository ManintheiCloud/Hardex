#!/usr/bin/env bash
# Runs the scan for the GitHub Action and exposes its exit code. Inputs come
# from environment variables, never interpolated into the script.
set -uo pipefail
args=(scan --profile "$PROFILE" --fail-on "$FAIL_ON" --format "$FORMAT" -o "$OUTPUT")
[ -n "${CONFIG:-}" ] && args+=(--config "$CONFIG")
# shellcheck disable=SC2206 # word splitting of space-separated lists is intended
extra=(${ARGS:-})
# shellcheck disable=SC2206
paths=(${PATHS:-.})
"$HARDEX" "${args[@]}" "${extra[@]}" "${paths[@]}"
code=$?
{ echo "report=$OUTPUT"; echo "exit-code=$code"; } >> "${GITHUB_OUTPUT:-/dev/null}"
if [ "$FORMAT" = sarif ] || [ "$FORMAT" = json ]; then
  echo "report written to $OUTPUT"
fi
exit $code
