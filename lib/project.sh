#!/usr/bin/env bash
sat_realpath(){ python3 - "$1" <<'P'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
P
}
sat_init_project(){ local root="$1" module="$2" requested="$3" root_real dest; root_real="$(sat_realpath "$root")"; dest="$(sat_realpath "$requested")"; case "$dest/" in "$root_real/"*) echo "Refusing workspace inside toolkit repo: $dest" >&2; exit 4;; esac; if [[ -e "$dest" ]] && [[ -n "$(find "$dest" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then echo "Destination not empty: $dest" >&2; exit 4; fi; mkdir -p "$dest"; cp -a "$root/modules/$module/template/." "$dest/"; [[ ! -f "$dest/target/TARGET.example.toml" || -f "$dest/target/TARGET.toml" ]] || cp "$dest/target/TARGET.example.toml" "$dest/target/TARGET.toml"; printf 'module = "%s"\ntoolkit_repo = "%s"\n' "$module" "$root_real" > "$dest/.security-agent-project"; find "$dest" -type f -name '*.sh' -exec chmod +x {} +; echo "[+] Initialized $module: $dest"; }
