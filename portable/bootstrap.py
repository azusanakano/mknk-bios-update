"""Root entry point inside the individually authorized, sealed helper ELF."""
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import zipfile


def stage_parent():
    # Native GI extensions need an executable mount. Both candidate directories
    # are OS-owned, and are checked before making a private random subdirectory.
    for parent in ("/run", "/var/cache"):
        try:
            info = os.lstat(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                continue
            if not os.statvfs(parent).f_flag & (os.ST_NOEXEC | os.ST_RDONLY):
                return parent
        except OSError:
            continue
    raise RuntimeError("端末サービスを一時展開できる管理者専用の実行領域を確認できません。")


def extract_payload(archive, stage):
    for entry in archive.infolist():
        if entry.filename == "__main__.py":
            continue
        parts = entry.filename.split("/")
        if (len(parts) < 3 or parts[0] != "payload" or parts[1] not in ("backend", "lib", "typelibs")
                or any(p in ("", ".", "..") or "\\" in p or ":" in p for p in parts)
                or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)):
            raise ValueError("ヘルパー内のファイル構成を確認できません。")
        dest = stage.joinpath(*parts[1:])
        dest.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(entry) as src, dest.open("xb") as out:
            shutil.copyfileobj(src, out)
        dest.chmod(0o644)
    # Workers may read public application resources. Only root can replace them.
    for directory, _, _ in os.walk(stage):
        if Path(directory) != stage:
            os.chmod(directory, 0o755)


def service_environment(stage, uid):
    return {"PATH": "/usr/bin:/bin", "HOME": "/", "LANG": "C.UTF-8", "PKEXEC_UID": uid,
            "LD_LIBRARY_PATH": str(stage / "lib"), "GI_TYPELIB_PATH": str(stage / "typelibs")}


def terminate(signum, frame):
    raise SystemExit(128 + signum)


def main():
    if sys.version_info[:2] != (3, 12):
        sys.exit("このポータブル版には OS の Python 3.12 が必要です。")
    if os.geteuid() != 0 or len(sys.argv) != 2 or not os.environ.get("PKEXEC_UID", "").isdecimal():
        sys.exit("更新画面から認証を行ってください。")
    signal.signal(signal.SIGTERM, terminate)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir=stage_parent(), prefix="mknk-bios-portable-") as dirname:
        stage = Path(dirname)
        with zipfile.ZipFile(sys.argv[0]) as archive:
            extract_payload(archive, stage)
        stage.chmod(0o711)
        service = stage / "backend" / "portable_service.py"
        proc = subprocess.Popen(["/usr/bin/python3", "-IBS", str(service), sys.argv[1]], cwd="/",
                                env=service_environment(stage, os.environ["PKEXEC_UID"]))
        try:
            return proc.wait()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        sys.exit(f"ポータブル版の端末サービスを起動できません。{exc}")
