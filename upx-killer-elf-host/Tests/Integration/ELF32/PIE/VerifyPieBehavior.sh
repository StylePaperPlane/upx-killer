#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

session=${1:?usage: VerifyPieBehavior.sh <session-directory> <packed|all>}
mode=${2:?usage: VerifyPieBehavior.sh <session-directory> <packed|all>}

run_case() {
  local image=$1
  local suffix=${2:-}
  set +e
  "$image" >"${image}${suffix}.stdout" 2>"${image}${suffix}.stderr"
  local code=$?
  set -e
  printf '%s' "$code" >"${image}${suffix}.exit"
}

assert_elf32_pie() {
  local image=$1
  readelf -h "$image" | grep 'Class:[[:space:]]*ELF32' >/dev/null
  readelf -h "$image" | grep 'Machine:[[:space:]]*Intel 80386' >/dev/null
  readelf -h "$image" | grep 'Type:[[:space:]]*DYN' >/dev/null
}

compare_behavior() {
  local original=$1
  local candidate=$2
  run_case "$candidate"
  cmp "${original}.stdout" "${candidate}.stdout"
  cmp "${original}.stderr" "${candidate}.stderr"
  cmp "${original}.exit" "${candidate}.exit"
}

for kind in dynamic static; do
  chmod 700 "$session/original-$kind"
  run_case "$session/original-$kind"
  assert_elf32_pie "$session/original-$kind"
  for variant in default lzma; do
    candidate="$session/packed-$kind-$variant"
    chmod 700 "$candidate"
    assert_elf32_pie "$candidate"
    compare_behavior "$session/original-$kind" "$candidate"
  done
done

test "$(cat "$session/original-dynamic.stdout")" = 'elf32-pie-dynamic:13'
test "$(cat "$session/original-dynamic.exit")" = '13'
test "$(cat "$session/original-static.stdout")" = 'elf32-pie-static:9'
test "$(cat "$session/original-static.exit")" = '9'

if [[ $mode == packed ]]; then
  exit 0
fi
test "$mode" = all

for kind in dynamic static; do
  original_entry=$(readelf -h "$session/original-$kind" | awk '/Entry point address:/ {print $4}')
  for variant in default lzma; do
    repaired="$session/unpacked-$kind-$variant"
    chmod 700 "$repaired"
    assert_elf32_pie "$repaired"
    repaired_entry=$(readelf -h "$repaired" | awk '/Entry point address:/ {print $4}')
    test "$repaired_entry" = "$original_entry"
    compare_behavior "$session/original-$kind" "$repaired"
    for run in 1 2 3; do
      run_case "$repaired" ".aslr-$run"
      cmp "$session/original-$kind.stdout" "${repaired}.aslr-$run.stdout"
      cmp "$session/original-$kind.stderr" "${repaired}.aslr-$run.stderr"
      cmp "$session/original-$kind.exit" "${repaired}.aslr-$run.exit"
    done
  done
done

for variant in default lzma; do
  dynamic="$session/unpacked-dynamic-$variant"
  readelf -l "$dynamic" | grep INTERP >/dev/null
  readelf -d "$dynamic" | grep -E 'NEEDED.*libc\.so\.6' >/dev/null
  readelf -SW "$dynamic" | grep '\.interp' >/dev/null
  readelf -SW "$dynamic" | grep '\.dynamic' >/dev/null
  readelf -SW "$dynamic" | grep '\.dynstr' >/dev/null
  readelf -SW "$dynamic" | grep '\.dynsym' >/dev/null
  readelf -SW "$dynamic" | grep '\.rel\.dyn' >/dev/null
  readelf -SW "$dynamic" | grep '\.rel\.plt' >/dev/null
  readelf -Wr "$dynamic" | grep R_386_RELATIVE >/dev/null
  readelf -Wr "$dynamic" | grep R_386_JUMP_SLOT >/dev/null

  static="$session/unpacked-static-$variant"
  ! readelf -l "$static" | grep INTERP >/dev/null
  ! readelf -d "$static" | grep NEEDED >/dev/null
  original_dynamic_count=$(readelf -l "$session/original-static" | grep -c DYNAMIC)
  repaired_dynamic_count=$(readelf -l "$static" | grep -c DYNAMIC)
  test "$repaired_dynamic_count" = "$original_dynamic_count"
done
