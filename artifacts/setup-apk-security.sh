#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE="$SCRIPT_DIR/opencode-apk-security-kit.zip"
DEST="${1:-$PWD/apk-security}"
PARENT="$(dirname "$DEST")"
STAGE="$PARENT/.security-agent-toolkit-apk.$$"

[ -f "$ARCHIVE" ] || { echo "Missing archive: $ARCHIVE" >&2; exit 1; }
[ ! -e "$DEST" ] || { echo "Destination already exists: $DEST" >&2; exit 1; }
mkdir -p "$PARENT" "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
unzip -q "$ARCHIVE" -d "$STAGE"
[ -d "$STAGE/apk-security" ] || { echo "Unexpected archive layout" >&2; exit 1; }
mv "$STAGE/apk-security" "$DEST"
chmod +x "$DEST/start-opencode.sh" "$DEST/install-tools-ubuntu.sh" "$DEST/tools/apk_prepare.py" 2>/dev/null || true
printf 'APK security workspace created: %s\n' "$DEST"
