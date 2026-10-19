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
case $code in
  0) ;;
  1) echo "::error title=hardex::findings at or above $FAIL_ON (see $OUTPUT)" ;;
  3) echo "::error title=hardex::assessment incomplete: some rules failed or inputs were unreadable" ;;
  *) echo "::error title=hardex::hardex scan exited $code (usage or input error)" ;;
esac
exit $code
