#!/usr/bin/env python3
from firmware_baseline_core import main as baseline_main
from firmware_baseline_enrich import main as enrich_main

if __name__ == "__main__":
    rc = baseline_main()
    if rc:
        raise SystemExit(rc)
    raise SystemExit(enrich_main())
