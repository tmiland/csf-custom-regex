#!/usr/bin/env bash
# Smoke tests for csf_custom_regex.sh.
# Safe to run anywhere: no root required, no system changes are made.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

script=./csf_custom_regex.sh
pass=0 fail=0
last_out=''

run() { # run "name" expected_rc cmd...
  local name="$1" want="$2" out rc
  shift 2
  out=$("$@" 2>&1)
  rc=$?
  last_out="$out"
  if [ "$rc" -eq "$want" ]; then
    pass=$((pass + 1))
    echo "ok - $name"
  else
    fail=$((fail + 1))
    echo "not ok - $name (exit $rc, want $want)"
    printf '%s\n' "$out" | sed 's/^/  # /'
  fi
}

run_codes() { # run_codes "name" "rc1 rc2..." cmd...  (any listed rc accepted)
  local name="$1" want="$2" out rc w ok=0
  shift 2
  out=$("$@" 2>&1)
  rc=$?
  last_out="$out"
  # shellcheck disable=SC2086
  for w in $want; do
    if [ "$rc" -eq "$w" ]; then ok=1; fi
  done
  if [ "$ok" -eq 1 ]; then
    pass=$((pass + 1))
    echo "ok - $name"
  else
    fail=$((fail + 1))
    echo "not ok - $name (exit $rc, want one of: $want)"
    printf '%s\n' "$out" | sed 's/^/  # /'
  fi
}

contains() { # contains "name" "needle"
  if printf '%s' "$last_out" | grep -qF -- "$2"; then
    pass=$((pass + 1))
    echo "ok - $1"
  else
    fail=$((fail + 1))
    echo "not ok - $1 (missing: $2)"
  fi
}

run 'syntax check' 0 bash -n "$script"

run '--help exits 0' 0 "$script" --help
contains '--help shows usage' 'Usage: csf_custom_regex.sh'

run '--version exits 0' 0 "$script" --version
contains '--version prints name' 'csf-custom-regex'

run 'unknown option exits 2' 2 "$script" --definitely-not-an-option

run 'no arguments shows usage' 1 "$script"

run '--dry-run exits 0' 0 "$script" --dry-run
contains '--dry-run reports OS' 'OS:'
contains '--dry-run makes no changes' 'no changes made'

run_codes '--check reports status' '0 1' "$script" --check
contains '--check mentions CSF' 'CSF:'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
