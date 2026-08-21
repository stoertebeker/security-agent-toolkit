#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import time

import apk_dynamic as runtime

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "dynamic"
OUT = REPORT / "setup-smoke.json"


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text()) if path.is_file() else {}
    except Exception:
        return {}


def capture_result(result: dict) -> None:
    _, dynamic = runtime.load_config(True)
    result["device_info"] = runtime.device_info(dynamic)
    root_path = REPORT / "root-status.json"
    if root_path.is_file():
        result["root_status"] = load_json(root_path)
    abi_path = REPORT / "abi-compatibility.json"
    if abi_path.is_file():
        result["abi_compatibility"] = load_json(abi_path)


def should_retry_with_google_apis() -> bool:
    setup = load_json(REPORT / "setup.json")
    abi = load_json(REPORT / "abi-compatibility.json")
    return (
        setup.get("runtime_abi_mode") == "android11-x86_64-multiabi-translation"
        and setup.get("image_tag") == "default"
        and not abi.get("compatible")
        and not abi.get("bridge_compatible")
    )


def rebuild_with_google_apis() -> None:
    original = runtime.choose_system_image

    def google_apis_image(cap: dict, dynamic: dict, meta: dict):
        forced = dict(dynamic)
        forced["image_tag"] = "google_apis"
        return original(cap, forced, meta)

    runtime.choose_system_image = google_apis_image
    runtime.setup()


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result = {
        "success": False,
        "elapsed_seconds": None,
        "device_info": None,
        "root_status": None,
        "abi_compatibility": None,
        "fallback_attempted": False,
        "fallback_reason": None,
        "error": None,
    }
    pending_error: BaseException | None = None

    try:
        # start() reuses reports/dynamic/setup.json when present and creates the
        # AVD only when setup has not been run yet. This makes /dynamic-setup
        # smoke-test the exact AVD it just prepared instead of recreating it.
        try:
            runtime.start()
            capture_result(result)
            result["success"] = True
        except BaseException as first_exc:
            # Android Emulator release notes document ARM/ARM64 app support on
            # Android 11 x86/x86_64 images, but current AOSP/default package
            # revisions may expose only native x86 ABIs and no active bridge.
            # The API-30 google_apis x86_64 image explicitly publishes ARM64 in
            # its product ABI list. Retry that managed image once rather than
            # weakening ABI validation or assuming translation exists.
            if should_retry_with_google_apis():
                result["fallback_attempted"] = True
                result["fallback_reason"] = (
                    "API-30 default x86_64 image booted without ARM native-bridge compatibility; "
                    "retrying managed google_apis x86_64 image"
                )
                runtime.stop()
                rebuild_with_google_apis()
                try:
                    runtime.start()
                    capture_result(result)
                    result["success"] = True
                except BaseException as second_exc:
                    pending_error = second_exc
                    result["error"] = str(second_exc)
            else:
                pending_error = first_exc
                result["error"] = str(first_exc)
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 1)
        OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            runtime.stop()
        except Exception:
            pass

    if pending_error is not None:
        raise pending_error

    print(f"[+] Dynamic setup smoke test passed in {result['elapsed_seconds']}s")
    if result["fallback_attempted"]:
        print("    compatibility fallback: google_apis x86_64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
