#!/usr/bin/env bash
set -euo pipefail

session=${1:?usage: VerifyBehavior.sh <session-directory>}
chmod 700 \
  "$session/original-exec" \
  "$session/packed-exec-default" \
  "$session/packed-exec-lzma" \
  "$session/unpacked-exec-default" \
  "$session/unpacked-exec-lzma"

run_case() {
  local image=$1
  set +e
  "$image" >"${image}.stdout" 2>"${image}.stderr"
  local code=$?
  set -e
  printf '%s' "$code" >"${image}.exit"
}

run_case "$session/original-exec"
for variant in default lzma; do
  run_case "$session/packed-exec-$variant"
  run_case "$session/unpacked-exec-$variant"
  cmp "$session/original-exec.stdout" "$session/packed-exec-$variant.stdout"
  cmp "$session/original-exec.stderr" "$session/packed-exec-$variant.stderr"
  cmp "$session/original-exec.exit" "$session/packed-exec-$variant.exit"
  cmp "$session/original-exec.stdout" "$session/unpacked-exec-$variant.stdout"
  cmp "$session/original-exec.stderr" "$session/unpacked-exec-$variant.stderr"
  cmp "$session/original-exec.exit" "$session/unpacked-exec-$variant.exit"
done

test "$(cat "$session/original-exec.stdout")" = 'elf32-plan:7'
test "$(cat "$session/original-exec.exit")" = '7'
