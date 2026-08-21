#!/usr/bin/env bash

sat_realpath() {
  python3 - "$1" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
}

sat_refuse_workspace_inside_repo() {
  local root_real="$1" dest="$2"
  case "$dest/" in
    "$root_real/"*)
      echo "Refusing workspace inside toolkit repo: $dest" >&2
      return 1
      ;;
  esac
}

sat_init_project() {
  local root="$1" module="$2" requested="$3" root_real dest
  root_real="$(sat_realpath "$root")"
  dest="$(sat_realpath "$requested")"
  sat_refuse_workspace_inside_repo "$root_real" "$dest" || exit 4

  if [[ -e "$dest" ]] && [[ -n "$(find "$dest" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    echo "Destination not empty: $dest" >&2
    exit 4
  fi

  mkdir -p "$dest"
  cp -a "$root/modules/$module/template/." "$dest/"
  [[ ! -f "$dest/target/TARGET.example.toml" || -f "$dest/target/TARGET.toml" ]] \
    || cp "$dest/target/TARGET.example.toml" "$dest/target/TARGET.toml"
  printf 'module = "%s"\ntoolkit_repo = "%s"\n' "$module" "$root_real" > "$dest/.security-agent-project"
  find "$dest" -type f -name '*.sh' -exec chmod +x {} +
  echo "[+] Initialized $module: $dest"
}

sat_project_module() {
  local metadata="$1"
  sed -n 's/^module = "\([^"]*\)"$/\1/p' "$metadata" | head -1
}

sat_sync_project() {
  local root="$1" module="$2" requested="$3" root_real dest metadata actual template
  root_real="$(sat_realpath "$root")"
  dest="$(sat_realpath "$requested")"
  sat_refuse_workspace_inside_repo "$root_real" "$dest" || exit 4

  metadata="$dest/.security-agent-project"
  if [[ ! -f "$metadata" ]]; then
    echo "Not a toolkit workspace (missing .security-agent-project): $dest" >&2
    exit 4
  fi

  actual="$(sat_project_module "$metadata")"
  if [[ "$actual" != "$module" ]]; then
    echo "Workspace module mismatch: requested=$module workspace=${actual:-unknown}" >&2
    exit 4
  fi

  template="$root/modules/$module/template"
  [[ -d "$template" ]] || {
    echo "Module template missing: $template" >&2
    exit 4
  }

  # Managed execution/orchestration files are refreshed in place. Extra local
  # files are retained, but template-owned paths with the same name are updated.
  for directory in .opencode tools; do
    if [[ -d "$template/$directory" ]]; then
      mkdir -p "$dest/$directory"
      cp -a "$template/$directory/." "$dest/$directory/"
    fi
  done

  for file in AGENTS.md START_PROMPT.txt opencode.json start.sh .gitignore; do
    [[ -e "$template/$file" ]] && cp -a "$template/$file" "$dest/$file"
  done

  # Refresh the example configuration but never overwrite the operator's active
  # TARGET.toml.
  if [[ -f "$template/target/TARGET.example.toml" ]]; then
    mkdir -p "$dest/target"
    cp -a "$template/target/TARGET.example.toml" "$dest/target/TARGET.example.toml"
  fi

  # Durable project records and artifact directories are operator/project state.
  # Add newly introduced template files only when the workspace does not already
  # contain them; never replace existing findings, reports, input or work data.
  for directory in findings reports input work; do
    [[ -d "$template/$directory" ]] || continue
    mkdir -p "$dest/$directory"
    cp -an "$template/$directory/." "$dest/$directory/"
  done

  printf 'module = "%s"\ntoolkit_repo = "%s"\n' "$module" "$root_real" > "$metadata"
  find "$dest" -type f -name '*.sh' -exec chmod +x {} +

  echo "[+] Synchronized $module workspace: $dest"
  echo "    refreshed: tools, .opencode, launcher/instructions, TARGET.example.toml"
  echo "    preserved: target/TARGET.toml, input, work, reports, existing findings"
}
