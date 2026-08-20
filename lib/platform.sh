#!/usr/bin/env bash
sat_detect_platform(){ . /etc/os-release; case "${ID:-}:${VERSION_ID:-}" in ubuntu:24.04) echo ubuntu-24.04;; ubuntu:26.04) echo ubuntu-26.04;; debian:12) echo debian-12;; debian:13) echo debian-13;; kali:*) echo kali-rolling;; parrot:7*|parrot:*7*) echo parrot-7;; *) echo unsupported;; esac; }
sat_require_supported_platform(){ SAT_PLATFORM="$(sat_detect_platform)"; export SAT_PLATFORM; [[ "$SAT_PLATFORM" != unsupported ]] || { echo 'Unsupported platform' >&2; exit 3; }; }
sat_print_platform(){ . /etc/os-release; printf 'Platform: %s\nDetected: %s\nArchitecture: %s\n' "$SAT_PLATFORM" "${PRETTY_NAME:-unknown}" "$(dpkg --print-architecture 2>/dev/null || uname -m)"; }
