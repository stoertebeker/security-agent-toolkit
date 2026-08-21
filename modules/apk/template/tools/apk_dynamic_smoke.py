#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import time

import apk_dynamic as runtime

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "dynamic"
OUT = REPORT / "setup-smoke.json"


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result = {
        "success": False,
        "elapsed_seconds": None,
        "device_info": None,
        "root_status": None,
        "error": None,
    }
    try:
        runtime.setup()
        runtime.start()
        _, dynamic = runtime.load_config(True)
        result["device_info"] = runtime.device_info(dynamic)
        root_path = REPORT / "root-status.json"
        if root_path.is_file():
            result["root_status"] = json.loads(root_path.read_text())
        result["success"] = True
    except BaseException as exc:
        result["error"] = str(exc)
        raise
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 1)
        OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            runtime.stop()
        except Exception:
            pass
    print(f"[+] Dynamic setup smoke test passed in {result['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
