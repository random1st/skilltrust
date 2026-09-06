#!/bin/bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  printf '%s\n' 'Usage: doctor.sh <CLAUDE_PLUGIN_DATA>' \
    'Run the pinned Axela doctor --json and return its result with doctor_exit_code.' \
    'Exit 1 from doctor is a reported finding. Bootstrap errors and other failures remain failures.'
  exit 0
fi
plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
binary=$("$plugin_root/scripts/bootstrap.sh" "$@")
if result=$("$binary" doctor --json --absolute-commands); then
  doctor_exit_code=0
else
  doctor_exit_code=$?
fi
case "$doctor_exit_code" in
  0|1)
    if [[ "$result" != \{*\} ]]; then
      printf 'Axela: doctor returned no JSON object; no successful verdict is available.\n' >&2
      exit 2
    fi
    printf '{"doctor_exit_code":%d,"result":%s}\n' "$doctor_exit_code" "$result"
    ;;
  *)
    printf 'Axela: doctor failed with exit %d; no successful verdict is available.\n' "$doctor_exit_code" >&2
    [[ -z "$result" ]] || printf '%s\n' "$result" >&2
    exit "$doctor_exit_code"
    ;;
esac
