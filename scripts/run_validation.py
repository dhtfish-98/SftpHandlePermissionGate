"""Build and verify source, sdist, and installed wheel from a repository root."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, cwd: Path, environment: dict[str, str], log: Path) -> None:
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=cwd, env=environment, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"validation failed: {log}")


def unpack_owned_sdist(archive: Path, target: Path) -> Path:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as stream:
        for entry in stream.getmembers():
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not (entry.isdir() or entry.isfile()):
                raise RuntimeError("unsupported source archive entry")
        stream.extractall(target, filter="data")
    roots = [item for item in target.iterdir() if item.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("unexpected source archive layout")
    return roots[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    if not (repo / "项目文档" / "README.md").is_file():
        raise RuntimeError("repository root must include 项目文档/README.md")
    build = args.build_root.resolve()
    build.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["SFTP_GATE_BUILD_DIR"] = str(build / "test-tmp")
    environment["PYTHONPATH"] = str(repo / "src")
    test_command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    run(test_command, cwd=repo, environment=environment, log=build / "source-tests.log")

    distribution = build / "dist"
    if distribution.exists():
        shutil.rmtree(distribution)
    distribution.mkdir(exist_ok=True)
    run(
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(distribution)],
        cwd=repo,
        environment=environment,
        log=build / "build.log",
    )
    source_archives = list(distribution.glob("*.tar.gz"))
    wheels = list(distribution.glob("*.whl"))
    if len(source_archives) != 1 or len(wheels) != 1:
        raise RuntimeError("expected exactly one source archive and wheel")
    sdist, wheel = source_archives[0], wheels[0]
    unpacked = unpack_owned_sdist(sdist, build / "unpacked")
    source_environment = environment.copy()
    source_environment["PYTHONPATH"] = str(unpacked / "src")
    run(test_command, cwd=unpacked, environment=source_environment, log=build / "sdist-tests.log")

    with zipfile.ZipFile(wheel) as archive:
        paths = archive.namelist()
    if not any(path.startswith("sftp_handle_permission_gate/") for path in paths):
        raise RuntimeError("wheel missing package")
    if any("weak_baseline" in path or path.startswith("tests/") for path in paths):
        raise RuntimeError("test-only weak baseline entered installed wheel")

    isolated = build / "isolated-venv"
    if isolated.exists():
        shutil.rmtree(isolated)
    run(
        ["uv", "venv", "--python", sys.executable, str(isolated)],
        cwd=build,
        environment=environment,
        log=build / "wheel-venv.log",
    )
    python = isolated / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(
        ["uv", "pip", "install", "--python", str(python), str(wheel)],
        cwd=build,
        environment=environment,
        log=build / "wheel-install.log",
    )
    installed_environment = environment.copy()
    installed_environment.pop("PYTHONPATH", None)
    installed_tests = build / "installed-tests"
    installed_tests.mkdir(exist_ok=True)
    run(
        [str(python), "-m", "unittest", "discover", "-s", str(unpacked / "tests"), "-v"],
        cwd=installed_tests,
        environment=installed_environment,
        log=build / "installed-tests.log",
    )
    run(
        [str(python), "-c", "import sftp_handle_permission_gate as gate; print(gate.__file__)"],
        cwd=installed_tests,
        environment=installed_environment,
        log=build / "installed-import.log",
    )
    installed_path = (build / "installed-import.log").read_text(encoding="utf-8").strip()
    if not installed_path.startswith(str(isolated)):
        raise RuntimeError("installed tests did not load the isolated wheel")

    receipt = {
        "status": "PASS_LOCAL_ONLY",
        "project": "SftpHandlePermissionGate",
        "version": "0.1.0",
        "python": sys.version.split()[0],
        "protocol": "SFTP v3",
        "dependency": "paramiko==5.0.0",
        "tests_per_surface": 13,
        "surfaces": ["source", "unpacked_sdist", "isolated_installed_wheel"],
        "asserted_boundaries": [
            "reader_read_allowed",
            "reader_write_and_rename_denied",
            "closed_cross_connection_and_restarted_handles_denied",
            "revocation_and_stale_path_denied",
            "concurrent_reader_denials_preserve_file_hash",
            "audit_decisions_checked",
        ],
        "wheel_excludes_weak_baseline": True,
        "sdist": {"file": sdist.name, "sha256": sha256(sdist)},
        "wheel": {"file": wheel.name, "sha256": sha256(wheel)},
        "logs": ["source-tests.log", "sdist-tests.log", "installed-tests.log", "wheel-install.log"],
        "open": ["real_authorized_target_evidence", "CVP_outcome", "public_release"],
    }
    receipt_path = build / "validation.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt_path)


if __name__ == "__main__":
    main()
