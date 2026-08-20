#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p tools

for spec in \
  "firmware-analysis:artifacts/setup-firmware-analysis.sh" \
  "api-pentest:artifacts/setup-api-pentest.sh" \
  "apk-security:artifacts/setup-apk-security.sh"
do
  name="${spec%%:*}"
  script="${spec#*:}"
  dest="$PWD/tools/$name"
  if [ -e "$dest" ]; then
    echo "[=] Already exists, leaving unchanged: $dest"
    continue
  fi
  echo "[+] Materializing $name"
  bash "$script" "$dest"
done

echo
echo "Editable workspaces are available under: $PWD/tools"
