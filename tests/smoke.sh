#!/usr/bin/env bash
set -euo pipefail
R="$(cd "$(dirname "$0")/.."&&pwd)"
bash -n "$R/toolkit" "$R"/lib/*.sh "$R"/modules/*/template/start.sh
python3 -m py_compile "$R"/lib/*.py "$R"/tests/repo_guard.py
while IFS= read -r -d '' path; do python3 -m py_compile "$path"; done < <(find "$R/modules" -path '*/template/tools/*.py' -type f -print0)
"$R/toolkit" validate
"$R/toolkit" repo-guard
"$R/toolkit" list
rm -rf /mnt/data/sat-init-test;"$R/toolkit" init api /mnt/data/sat-init-test
test -f /mnt/data/sat-init-test/target/TARGET.toml
