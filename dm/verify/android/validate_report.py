#!/usr/bin/env python3
"""Validate synthetic diagnostic evidence without promoting game runtime gates."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

REQUIRED_CHECKS = ("abi", "wx", "tls", "x18", "hle", "signal", "thread", "vulkan")


def summarize(report):
    if report.get("schemaVersion") != 1 or report.get("gamePlayable") is not False:
        raise ValueError("Expected Phase 0 schema v1 and explicit gamePlayable=false")
    checks = report.get("checks", [])
    if not isinstance(checks, list) or any(not isinstance(c, dict) for c in checks):
        raise ValueError("checks must be an array of objects")
    ids = [c.get("id") for c in checks]
    complete = len(ids) == len(REQUIRED_CHECKS) and set(ids) == set(REQUIRED_CHECKS)
    passed = complete and all(c.get("status") == "PASS" for c in checks)
    return {
        "schemaVersion": 1,
        "phase0Probes": "PASS" if passed else "FAIL",
        "checks": checks,
        "gates": {"G0": "NOT_VERIFIED", **{f"G{i}": "NOT_RUN" for i in range(1, 7)}},
        "gamePlayable": False,
        "limitations": [
            "Only self-authored ARM64 fixtures were executed; no NSO or game assets.",
            "Upstream loader, rewritten TLS, red-zone removal and guest stack signals remain untested.",
            "Vulkan device creation is not NVN replay or frame validation.",
        ],
    }


def verify_apk(apk):
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        required = {"AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libd2r_diagnostics.so"}
        if not required.issubset(names):
            raise ValueError("APK is missing manifest, bytecode, or ARM64 diagnostic library")
        if any(n.startswith("lib/") and not n.startswith("lib/arm64-v8a/") for n in names):
            raise ValueError("Diagnostic APK must contain only arm64-v8a libraries")
    return hashlib.sha256(apk.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--build-log", type=Path)
    parser.add_argument("--install-log", type=Path)
    parser.add_argument("--install-metadata", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8-sig"))
    result = summarize(report)
    if all((args.apk, args.build_log, args.install_log, args.install_metadata)):
        build = args.build_log.read_text(encoding="utf-8-sig")
        install = args.install_log.read_text(encoding="utf-8-sig")
        if "BUILD SUCCESSFUL" not in build or "Success" not in install.splitlines():
            raise ValueError("Build/install logs do not confirm G0")
        digest = verify_apk(args.apk)
        installed = json.loads(args.install_metadata.read_text(encoding="utf-8-sig"))
        if installed.get("installedApkSha256") != digest or installed.get("package") != "org.d2rmobile.diagnostics":
            raise ValueError("Installed APK evidence does not match supplied APK")
        if not installed.get("deviceModel") or installed.get("deviceModel") != report.get("device", {}).get("model"):
            raise ValueError("Installed device does not match diagnostic report")
        result["apkSha256"] = digest
        result["installation"] = installed
        result["gates"]["G0"] = "PASS"
    result["device"] = report.get("device", {})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"phase0Probes": result["phase0Probes"], "gates": result["gates"]}))
    return 0 if result["phase0Probes"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
