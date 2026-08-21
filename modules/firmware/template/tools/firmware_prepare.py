#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "target" / "TARGET.toml"
SAT_HOME = Path(os.environ.get("SAT_HOME", Path.home() / ".local/share/security-agent-toolkit"))
WORK = ROOT / "work"
TMP = WORK / "tmp"
EXTRACT = WORK / "extracted"
REPORT = ROOT / "reports" / "tool-output"
STATE = REPORT / "firmware-preparation.json"

ROOTFS_MARKERS = {
    "etc/passwd": 6,
    "etc/shadow": 2,
    "etc/init.d": 3,
    "etc/inittab": 2,
    "sbin/init": 4,
    "bin/busybox": 4,
    "usr/sbin": 1,
    "usr/bin": 1,
    "lib": 1,
    "www": 2,
    "var/www": 2,
}


def fail(message: str) -> None:
    raise SystemExit(f"[!] {message}")


def load_config() -> tuple[dict, dict]:
    if not TARGET.is_file():
        fail("target/TARGET.toml missing")
    with TARGET.open("rb") as handle:
        cfg = tomllib.load(handle)
    if not cfg.get("engagement", {}).get("authorized", False):
        fail("engagement.authorized=false")
    return cfg, cfg.get("firmware", {})


def target_path(fw: dict) -> Path:
    raw = fw.get("path")
    if not raw:
        fail("firmware.path missing")
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    if not path.is_file():
        fail(f"firmware image not found: {path}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def env() -> dict[str, str]:
    result = os.environ.copy()
    system_paths = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    result.update({
        "PATH": f"{SAT_HOME / 'bin'}:{system_paths}:{result.get('PATH', '')}",
        "TMPDIR": str(TMP),
        "TMP": str(TMP),
        "TEMP": str(TMP),
    })
    return result


def which(name: str) -> str | None:
    return shutil.which(name, path=env()["PATH"])


def run(command: list[str], timeout: int | None = 1200) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env(),
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def audit_extraction(root: Path) -> dict:
    files = dirs = symlinks = specials = 0
    absolute_links: list[dict] = []
    escaping_links: list[dict] = []
    total_bytes = 0
    root_resolved = root.resolve()

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs += len(dirnames)
        for name in filenames:
            path = current_path / name
            try:
                st = path.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                symlinks += 1
                try:
                    raw_target = os.readlink(path)
                    target = Path(raw_target)
                    if target.is_absolute():
                        absolute_links.append({"path": relative(path), "target": raw_target})
                    else:
                        resolved = (path.parent / target).resolve(strict=False)
                        try:
                            resolved.relative_to(root_resolved)
                        except ValueError:
                            escaping_links.append({"path": relative(path), "target": raw_target})
                except OSError:
                    pass
            elif stat.S_ISREG(st.st_mode):
                files += 1
                total_bytes += int(st.st_size)
            else:
                specials += 1

    return {
        "files": files,
        "directories": dirs,
        "symlinks": symlinks,
        "special_entries": specials,
        "regular_file_bytes": total_bytes,
        "absolute_symlink_count": len(absolute_links),
        "escaping_symlink_count": len(escaping_links),
        "absolute_symlink_examples": absolute_links[:50],
        "escaping_symlink_examples": escaping_links[:50],
    }


def marker_exists_without_following(base: Path, marker: str) -> bool:
    parts = Path(marker).parts
    current = base
    for index, part in enumerate(parts):
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return index == len(parts) - 1
        if index < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
            return False
    return True


def real_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def rootfs_candidates(root: Path, limit: int) -> list[dict]:
    scores: dict[Path, dict] = {}

    def score(path: Path) -> tuple[int, list[str]]:
        total = 0
        markers = []
        for marker, points in ROOTFS_MARKERS.items():
            if marker_exists_without_following(path, marker):
                total += points
                markers.append(marker)
        return total, markers

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = [name for name in dirnames if real_directory(current_path / name)]

        candidate_dirs: list[Path] = []
        if current_path.name == "etc" and ("passwd" in filenames or "inittab" in filenames):
            candidate_dirs.append(current_path.parent)
        if current_path.name == "bin" and "busybox" in filenames:
            candidate_dirs.append(current_path.parent)
        if current_path.name == "sbin" and "init" in filenames:
            candidate_dirs.append(current_path.parent)

        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            continue
        if depth <= 8:
            candidate_dirs.append(current_path)

        for candidate in dict.fromkeys(candidate_dirs):
            if not real_directory(candidate):
                continue
            total, markers = score(candidate)
            if not total:
                continue
            previous = scores.get(candidate)
            if previous is None or total > previous["score"]:
                scores[candidate] = {"path": relative(candidate), "score": total, "markers": markers}

    return sorted(scores.values(), key=lambda item: (-item["score"], item["path"]))[:limit]


def write_text_summary(state: dict) -> None:
    lines = [
        "# Firmware preparation",
        f"input: {state['input']}",
        f"sha256: {state['sha256']}",
        f"file: {state.get('file_description') or 'unknown'}",
        f"binwalk status: {state.get('binwalk_status')}",
        f"unblob status: {state['unblob']['status']}",
        f"unblob exit code: {state['unblob'].get('exit_code')}",
        f"extraction files: {state['extraction_audit']['files']}",
        f"extraction directories: {state['extraction_audit']['directories']}",
        f"symlinks: {state['extraction_audit']['symlinks']}",
        f"absolute symlinks: {state['extraction_audit']['absolute_symlink_count']}",
        f"escaping symlinks: {state['extraction_audit']['escaping_symlink_count']}",
        f"rootfs candidates: {len(state['rootfs_candidates'])}",
        f"primary rootfs: {state.get('primary_rootfs') or 'not established'}",
        f"coverage: {state['coverage']}",
        "",
        "## Rootfs candidates",
    ]
    for item in state["rootfs_candidates"]:
        lines.append(f"- score={item['score']:2d} {item['path']} markers={','.join(item['markers'])}")
    if state.get("limitations"):
        lines += ["", "## Limitations"] + [f"- {item}" for item in state["limitations"]]
    (REPORT / "firmware-preparation.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    _, fw = load_config()
    image = target_path(fw)
    TMP.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    digest = sha256(image)

    force = "--force" in sys.argv[1:]
    if STATE.is_file() and not force:
        try:
            old = json.loads(STATE.read_text())
            primary = old.get("primary_rootfs")
            primary_ok = bool(primary and real_directory(ROOT / primary))
            extracted_files = int(old.get("extraction_audit", {}).get("files", 0))
            unblob_status = old.get("unblob", {}).get("status")
            reusable = (
                old.get("sha256") == digest
                and real_directory(EXTRACT)
                and unblob_status != "missing"
                and (primary_ok or extracted_files > 0)
            )
            if reusable:
                print("[=] Preparation artifacts are fresh for the current firmware image")
                return 0
        except Exception:
            pass

    if EXTRACT.exists():
        shutil.rmtree(EXTRACT)
    EXTRACT.mkdir(parents=True)

    file_proc = run(["file", "-b", str(image)], timeout=60)
    file_description = (file_proc.stdout or "").strip()
    (REPORT / "firmware-file.txt").write_text((file_proc.stdout or "") + ("" if (file_proc.stdout or "").endswith("\n") else "\n"), encoding="utf-8")

    binwalk_path = which("binwalk")
    binwalk_status = "missing"
    if binwalk_path:
        proc = run([binwalk_path, str(image)], timeout=600)
        (REPORT / "firmware-binwalk.txt").write_text(proc.stdout or "", encoding="utf-8")
        binwalk_status = "ok" if proc.returncode == 0 else f"exit-{proc.returncode}"
    else:
        (REPORT / "firmware-binwalk.txt").write_text("binwalk not found in managed/system PATH\n", encoding="utf-8")

    unblob_path = which("unblob")
    unblob_info = {"status": "missing", "exit_code": None, "path": None}
    if unblob_path:
        dependency_proc = run([unblob_path, "--show-external-dependencies"], timeout=120)
        (REPORT / "unblob-dependencies.txt").write_text(dependency_proc.stdout or "", encoding="utf-8")
        depth = int(fw.get("extract_depth", 10))
        processes = int(fw.get("extract_processes", min(4, os.cpu_count() or 1)))
        report_path = REPORT / "unblob-report.json"
        proc = run([
            unblob_path, "-e", str(EXTRACT), "-d", str(depth), "-p", str(processes),
            "--report", str(report_path), str(image),
        ], timeout=int(fw.get("extract_timeout_seconds", 3600)))
        (REPORT / "unblob.txt").write_text(proc.stdout or "", encoding="utf-8")
        unblob_info = {"status": "ok" if proc.returncode == 0 else "degraded", "exit_code": proc.returncode, "path": unblob_path}
    else:
        (REPORT / "unblob-dependencies.txt").write_text("unblob not found in managed/system PATH\n", encoding="utf-8")
        (REPORT / "unblob.txt").write_text("unblob not found in managed/system PATH\n", encoding="utf-8")

    audit = audit_extraction(EXTRACT)
    candidates = rootfs_candidates(EXTRACT, int(fw.get("max_rootfs_candidates", 20)))
    primary = candidates[0]["path"] if candidates else None
    limitations: list[str] = []
    coverage = "complete"

    if unblob_info["status"] == "missing":
        coverage = "degraded"
        limitations.append(f"unblob is unavailable in managed/system PATH; expected managed location is {SAT_HOME / 'bin' / 'unblob'}")
    elif unblob_info["status"] == "degraded":
        coverage = "degraded"
        limitations.append(f"unblob returned exit code {unblob_info['exit_code']}; see reports/tool-output/unblob.txt")
    if not candidates:
        coverage = "degraded"
        limitations.append("no conventional root filesystem candidate was established; later analysis must treat the extraction tree as unstructured")
    if audit["escaping_symlink_count"]:
        limitations.append("extracted filesystem contains relative symlinks that resolve outside the extraction root; analysis must not follow them")
    if audit["absolute_symlink_count"]:
        limitations.append("extracted filesystem contains absolute symlinks; analysis must interpret them as target-root paths and never follow them on the host")

    state = {
        "schema_version": 1,
        "prepared_at": int(time.time()),
        "input": relative(image),
        "sha256": digest,
        "size": image.stat().st_size,
        "file_description": file_description,
        "binwalk_status": binwalk_status,
        "unblob": unblob_info,
        "extraction_root": relative(EXTRACT),
        "extraction_audit": audit,
        "rootfs_candidates": candidates,
        "primary_rootfs": primary,
        "coverage": coverage,
        "limitations": limitations,
    }
    STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (REPORT / "firmware.sha256").write_text(f"{digest}  {relative(image)}\n", encoding="utf-8")
    write_text_summary(state)

    print(f"[+] Firmware preparation complete: {coverage}")
    print(f"    primary rootfs: {primary or 'not established'}")
    print(f"    files: {audit['files']} symlinks: {audit['symlinks']}")
    if limitations:
        for item in limitations:
            print(f"    limitation: {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
