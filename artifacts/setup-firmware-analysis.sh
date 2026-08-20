#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE="$SCRIPT_DIR/opencode-firmware-analysis-kit.zip"
DEST="${1:-$PWD/firmware-analysis}"
PARENT="$(dirname "$DEST")"
NAME="$(basename "$DEST")"
STAGE="$PARENT/.security-agent-toolkit-firmware.$$"

[ -f "$ARCHIVE" ] || { echo "Missing archive: $ARCHIVE" >&2; exit 1; }
[ ! -e "$DEST" ] || { echo "Destination already exists: $DEST" >&2; exit 1; }
mkdir -p "$PARENT" "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
unzip -q "$ARCHIVE" -d "$STAGE"
[ -d "$STAGE/firmware-analysis" ] || { echo "Unexpected archive layout" >&2; exit 1; }
mv "$STAGE/firmware-analysis" "$DEST"
chmod +x "$DEST/start-opencode.sh" 2>/dev/null || true
printf 'Firmware analysis workspace created: %s\n' "$DEST"
