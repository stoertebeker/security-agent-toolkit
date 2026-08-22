# PE / EXE malware module

Static-first Windows PE malware analysis. The module never executes the target binary on the analysis host.

```bash
./toolkit install pe
./toolkit init pe ~/security-work/sample-pe
cd ~/security-work/sample-pe
cp /path/to/sample.exe input/sample.exe
# edit target/TARGET.toml and set engagement.authorized=true
./start.sh
```

Then run `/analyze`.
