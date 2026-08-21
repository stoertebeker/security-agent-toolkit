# Firmware module

Static, evidence-first firmware security analysis with deterministic extraction/rootfs discovery, filesystem/service/update/ELF baselines, group-first credential triage, focused binary reversing and bounded public research.

Install and create a local workspace:

```bash
./toolkit install firmware
./toolkit init firmware ~/security-work/router-review
cd ~/security-work/router-review
cp /path/to/firmware.bin input/firmware.bin
cp target/TARGET.example.toml target/TARGET.toml
# Set engagement.authorized=true and adjust firmware.path/settings.
```

Prepare deterministically:

```bash
python3 tools/firmware_prepare.py
python3 tools/firmware_baseline.py
python3 tools/firmware_component_fingerprint.py
python3 tools/firmware_secret_scan.py
python3 tools/firmware_secret_group.py
```

Then start OpenCode:

```bash
./start.sh
```

Targeted commands:

```text
/prepare
/secrets
/services
/binaries
/update
/research
/summary
```

Detailed architecture and evidence boundaries are documented in `docs/FIRMWARE_ANALYSIS_PIPELINE.md` at the toolkit root.

The v1 module is static-only and never executes target binaries. Service configuration/startup evidence is not treated as proof of actual LAN/WAN exposure; bootloader/secure-boot/runtime/hardware/cloud questions remain explicit limitations unless separately established.
