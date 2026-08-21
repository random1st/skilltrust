#!/usr/bin/env bash
set -euo pipefail

audit_requirements="$(mktemp "${TMPDIR:-/tmp}/skilltrust-audit.XXXXXX")"

cleanup() {
  rm -f -- "$audit_requirements"
}
trap cleanup EXIT

uv export \
  --frozen \
  --all-extras \
  --no-emit-project \
  --format requirements.txt \
  --output-file "$audit_requirements"

uv run pip-audit \
  --strict \
  --require-hashes \
  --disable-pip \
  --progress-spinner off \
  --requirement "$audit_requirements"
