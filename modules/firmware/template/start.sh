#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p \
  work/tmp work/cache work/extracted \
  reports/subagents reports/tool-output reports/research \
  findings
export TMPDIR="$PWD/work/tmp" TMP="$PWD/work/tmp" TEMP="$PWD/work/tmp" XDG_CACHE_HOME="$PWD/work/cache" OPENCODE_ENABLE_EXA=1
SAT_HOME="${SAT_HOME:-$HOME/.local/share/security-agent-toolkit}"
export SAT_HOME PATH="$SAT_HOME/bin:$PATH"
O="$SAT_HOME/bin/opencode"
[[ -x "$O" ]] || O="$(command -v opencode || true)"
[[ -n "$O" ]] || { echo "OpenCode missing. Run: ./toolkit install firmware" >&2; exit 1; }
exec "$O" --agent firmware-security
