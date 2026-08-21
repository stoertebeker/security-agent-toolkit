#!/usr/bin/env bash

SAT_CATALOG="$ROOT/dependencies/catalog.toml"

sat_sudo() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

sat_catalog() {
  python3 - "$SAT_CATALOG" "$1" "$2" <<'PY'
import sys, tomllib
path, dep, field = sys.argv[1:]
with open(path, 'rb') as handle:
    value = tomllib.load(handle)['dependencies'][dep].get(field, '')
print('\n'.join(value) if isinstance(value, list) else value)
PY
}

sat_uv_environment() {
  export UV_TOOL_BIN_DIR="$SAT_HOME/bin"
  export UV_TOOL_DIR="$SAT_HOME/python-tools"
  export UV_PYTHON_INSTALL_DIR="$SAT_HOME/python"
  export UV_PYTHON_BIN_DIR="$SAT_HOME/bin"
  export UV_CACHE_DIR="$SAT_HOME/cache/uv"
}

sat_dependency_path() {
  # Non-login shells and some minimal/container environments omit sbin paths,
  # even though distro packages legitimately install helper tools there.
  printf '%s' "$SAT_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
}

sat_check_dependency() {
  local command
  command="$(sat_catalog "$1" check)"
  PATH="$(sat_dependency_path)" bash -c "$command" >/dev/null 2>&1
}

sat_doctor_dependency() {
  if sat_check_dependency "$1"; then
    printf '  ✓ %s\n' "$1"
  else
    printf '  ✗ %s\n' "$1"
  fi
}

sat_install_apt() {
  mapfile -t packages < <(sat_catalog "$1" packages)
  sat_sudo apt-get update
  sat_sudo apt-get install -y "${packages[@]}"
}

sat_install_dependency() {
  local dependency="$1" kind handler

  if sat_check_dependency "$dependency"; then
    echo "[=] $dependency"
    return
  fi

  kind="$(sat_catalog "$dependency" kind)"
  echo "[+] $dependency"

  if [[ "$kind" == "apt" ]]; then
    sat_install_apt "$dependency"
  else
    handler="$(sat_catalog "$dependency" handler)"
    "$handler" "$dependency"
  fi

  sat_check_dependency "$dependency" || {
    echo "Install check failed: $dependency" >&2
    return 1
  }
}

install_opencode() {
  mkdir -p "$SAT_HOME/bin"
  curl -fsSL https://opencode.ai/install | OPENCODE_INSTALL_DIR="$SAT_HOME/bin" bash
}

install_uv() {
  mkdir -p "$SAT_HOME/bin" "$SAT_HOME/cache/uv" "$SAT_HOME/python" "$SAT_HOME/python-tools"
  curl -LsSf https://astral.sh/uv/install.sh \
    | env UV_UNMANAGED_INSTALL="$SAT_HOME/bin" sh

  [[ -x "$SAT_HOME/bin/uv" ]] || {
    echo "uv installer completed but $SAT_HOME/bin/uv was not created" >&2
    return 1
  }
}

install_python_tool() {
  local dependency="$1" package executable
  package="$(sat_catalog "$dependency" package)"
  executable="$(sat_catalog "$dependency" executable)"

  sat_install_dependency uv
  sat_uv_environment
  mkdir -p "$UV_TOOL_BIN_DIR" "$UV_TOOL_DIR" "$UV_PYTHON_INSTALL_DIR" "$UV_CACHE_DIR"
  "$SAT_HOME/bin/uv" python install 3.12
  "$SAT_HOME/bin/uv" tool install --force --python 3.12 "$package"

  [[ -x "$SAT_HOME/bin/$executable" ]] || {
    echo "uv installed $package but executable $SAT_HOME/bin/$executable is missing" >&2
    return 1
  }
}

install_unblob() {
  local dependency="$1"
  install_python_tool "$dependency"

  local real_unblob="$SAT_HOME/python-tools/unblob/bin/unblob"
  [[ -x "$real_unblob" ]] || {
    echo "unblob tool environment missing expected executable: $real_unblob" >&2
    return 1
  }

  # uv exposes only the requested tool entry point in UV_TOOL_BIN_DIR. unblob's
  # extractor dependency checks also need console scripts provided by Python
  # dependencies such as jefferson and ubi-reader. Wrap unblob so its complete
  # tool-environment bin directory and distro sbin paths are visible to itself
  # and to subprocess extractors without polluting the user's interactive PATH.
  rm -f "$SAT_HOME/bin/unblob"
  cat > "$SAT_HOME/bin/unblob" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SAT_RUNTIME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export PATH="$SAT_RUNTIME/python-tools/unblob/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
exec "$SAT_RUNTIME/python-tools/unblob/bin/unblob" "$@"
EOF
  chmod +x "$SAT_HOME/bin/unblob"
}

install_jdk21() {
  mkdir -p "$SAT_HOME/java" "$SAT_HOME/bin" "$SAT_HOME/cache"
  local architecture url archive extracted

  case "$(uname -m)" in
    x86_64) architecture=x64 ;;
    aarch64|arm64) architecture=aarch64 ;;
    *) echo "Unsupported architecture for JDK 21: $(uname -m)" >&2; return 1 ;;
  esac

  url="$(curl -fsSL "https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=$architecture&image_type=jdk&os=linux&vendor=eclipse" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["binary"]["package"]["link"])')"
  archive="$SAT_HOME/cache/jdk21.tgz"

  curl -fL "$url" -o "$archive"
  rm -rf "$SAT_HOME/java/jdk-21" "$SAT_HOME/java/extract"
  mkdir -p "$SAT_HOME/java/extract"
  tar -xzf "$archive" -C "$SAT_HOME/java/extract"
  extracted="$(find "$SAT_HOME/java/extract" -mindepth 1 -maxdepth 1 -type d | head -1)"
  mv "$extracted" "$SAT_HOME/java/jdk-21"
  rm -rf "$SAT_HOME/java/extract"
  ln -sf "$SAT_HOME/java/jdk-21/bin/java" "$SAT_HOME/bin/java"
}

install_ghidra() {
  sat_install_dependency jdk21
  mkdir -p "$SAT_HOME/tools" "$SAT_HOME/cache" "$SAT_HOME/bin"
  local url archive extracted

  url="$(curl -fsSL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(a["browser_download_url"] for a in d["assets"] if a["name"].endswith(".zip")))')"
  archive="$SAT_HOME/cache/ghidra.zip"

  curl -fL "$url" -o "$archive"
  rm -rf "$SAT_HOME/tools/ghidra" "$SAT_HOME/tools/extract-ghidra"
  mkdir -p "$SAT_HOME/tools/extract-ghidra"
  unzip -q "$archive" -d "$SAT_HOME/tools/extract-ghidra"
  extracted="$(find "$SAT_HOME/tools/extract-ghidra" -mindepth 1 -maxdepth 1 -type d | head -1)"
  mv "$extracted" "$SAT_HOME/tools/ghidra"
  rm -rf "$SAT_HOME/tools/extract-ghidra"
  ln -sf "$SAT_HOME/tools/ghidra/support/analyzeHeadless" "$SAT_HOME/bin/analyzeHeadless"
}

install_jadx() {
  sat_install_dependency jdk21
  mkdir -p "$SAT_HOME/tools/jadx" "$SAT_HOME/cache" "$SAT_HOME/bin"
  local url

  url="$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(a["browser_download_url"] for a in d["assets"] if a["name"].startswith("jadx-") and a["name"].endswith(".zip")))')"
  curl -fL "$url" -o "$SAT_HOME/cache/jadx.zip"
  rm -rf "$SAT_HOME/tools/jadx"
  mkdir -p "$SAT_HOME/tools/jadx"
  unzip -q "$SAT_HOME/cache/jadx.zip" -d "$SAT_HOME/tools/jadx"
  ln -sf "$SAT_HOME/tools/jadx/bin/jadx" "$SAT_HOME/bin/jadx"
}

install_apktool() {
  sat_install_dependency jdk21
  mkdir -p "$SAT_HOME/tools/apktool" "$SAT_HOME/bin"
  local url

  url="$(curl -fsSL https://api.github.com/repos/iBotPeaches/Apktool/releases/latest \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(a["browser_download_url"] for a in d["assets"] if a["name"].startswith("apktool_") and a["name"].endswith(".jar")))')"
  curl -fL "$url" -o "$SAT_HOME/tools/apktool/apktool.jar"
  printf '#!/usr/bin/env bash\nexec "%s/bin/java" -jar "%s/tools/apktool/apktool.jar" "$@"\n' "$SAT_HOME" "$SAT_HOME" > "$SAT_HOME/bin/apktool"
  chmod +x "$SAT_HOME/bin/apktool"
}

install_android_emulator() {
  sat_install_dependency jdk21

  case "$(uname -m)" in
    x86_64) ;;
    *)
      echo "Managed Android Emulator runtime currently supports Linux x86_64 hosts only; static APK analysis remains supported on this host." >&2
      return 1
      ;;
  esac

  sat_sudo apt-get update
  sat_sudo apt-get install -y \
    libdbus-1-3 libfontconfig1 libgl1 libnss3 libvulkan1 \
    libx11-6 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 \
    libxkbcommon-x11-0 libxrandr2 libxtst6 libxcb1 libxcb-cursor0

  local sdk="$SAT_HOME/android-sdk"
  local archive="$SAT_HOME/cache/android-commandlinetools.zip"
  local extract="$SAT_HOME/cache/android-commandlinetools-extract"
  local cli_version="15859902"
  local url="https://dl.google.com/android/repository/commandlinetools-linux-${cli_version}_latest.zip"

  mkdir -p "$SAT_HOME/cache" "$SAT_HOME/bin" "$sdk/cmdline-tools"
  curl -fL "$url" -o "$archive"
  rm -rf "$extract" "$sdk/cmdline-tools/latest"
  mkdir -p "$extract" "$sdk/cmdline-tools/latest"
  unzip -q "$archive" -d "$extract"
  cp -a "$extract/cmdline-tools/." "$sdk/cmdline-tools/latest/"
  rm -rf "$extract"

  export ANDROID_SDK_ROOT="$sdk" ANDROID_HOME="$sdk"
  export JAVA_HOME="$SAT_HOME/java/jdk-21"
  export PATH="$JAVA_HOME/bin:$sdk/cmdline-tools/latest/bin:$sdk/platform-tools:$sdk/emulator:$PATH"

  yes | "$sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$sdk" --licenses >/dev/null || true
  "$sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$sdk" --install "platform-tools" "emulator"

  ln -sf "$sdk/cmdline-tools/latest/bin/sdkmanager" "$SAT_HOME/bin/sdkmanager"
  ln -sf "$sdk/cmdline-tools/latest/bin/avdmanager" "$SAT_HOME/bin/avdmanager"
  ln -sf "$sdk/platform-tools/adb" "$SAT_HOME/bin/adb"
  ln -sf "$sdk/emulator/emulator" "$SAT_HOME/bin/emulator"
}

install_rust() {
  mkdir -p "$SAT_HOME/rust" "$SAT_HOME/bin"
  export RUSTUP_HOME="$SAT_HOME/rust/rustup"
  export CARGO_HOME="$SAT_HOME/rust/cargo"

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --no-modify-path

  ln -sf "$CARGO_HOME/bin/cargo" "$SAT_HOME/bin/cargo"
  ln -sf "$CARGO_HOME/bin/rustc" "$SAT_HOME/bin/rustc"
}

install_binwalk() {
  sat_install_dependency rust
  export RUSTUP_HOME="$SAT_HOME/rust/rustup"
  export CARGO_HOME="$SAT_HOME/rust/cargo"
  "$CARGO_HOME/bin/cargo" install binwalk --force --root "$SAT_HOME"
}

sat_install_core() {
  local dependency
  for dependency in ca-certificates curl python3 unzip; do
    sat_install_dependency "$dependency"
  done
  sat_install_dependency opencode
  sat_install_dependency uv
}
