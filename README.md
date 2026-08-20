# Security Agent Toolkit
Modular OpenCode security-analysis toolkit. This repository contains only framework code and templates. Real assessment data always lives in a separate workspace outside the checkout.

Supported: Ubuntu 24.04/26.04, Debian 12/13, Kali Rolling, Parrot OS 7.x.

```bash
./toolkit list
./toolkit doctor apk
./toolkit install apk
./toolkit init apk ~/security-work/my-app
cd ~/security-work/my-app
cp /path/app.apk input/app.apk
nano target/TARGET.toml
./start.sh
```

OpenCode is installed as a core dependency. No QEMU/emulator/Docker/KVM stack is installed.
