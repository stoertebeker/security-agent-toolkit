#!/usr/bin/env python3
from firmware_identity import main as identity_main
from firmware_baseline_core import main as baseline_main
from firmware_baseline_enrich import main as enrich_main
from firmware_web_surface import main as web_surface_main

if __name__ == "__main__":
    rc = identity_main()
    if rc:
        raise SystemExit(rc)
    rc = baseline_main()
    if rc:
        raise SystemExit(rc)
    rc = enrich_main()
    if rc:
        raise SystemExit(rc)
    raise SystemExit(web_surface_main())
