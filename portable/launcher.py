#!/usr/bin/python3 -IBS
"""AppRun. Only the small GUI executable is copied on an ordinary launch."""
import errno
import os
from pathlib import Path
import shutil
import sys


def sealed_gui(path):
    import fcntl
    flags = os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
    try:
        fd = os.memfd_create("mknk-bios-update", flags | getattr(os, "MFD_EXEC", 0x10))
    except OSError as exc:
        if exc.errno != errno.EINVAL:
            raise
        fd = os.memfd_create("mknk-bios-update", flags)
    try:
        with path.open("rb") as source, os.fdopen(os.dup(fd), "wb") as target:
            shutil.copyfileobj(source, target)
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def main():
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        sys.exit("この AppImage はデスクトップの通常ユーザーで開いてください。")
    root = Path(__file__).resolve().parent
    image_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    os.set_inheritable(image_fd, True)
    env = dict(os.environ, MKNK_BIOS_PORTABLE="1", MKNK_BIOS_PORTABLE_DIR_FD=str(image_fd),
               LD_LIBRARY_PATH=str(root / "usr/lib/gui"))
    env["XDG_DATA_DIRS"] = str(root / "usr/share") + ":" + (env.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share")
    # The privileged observer can hash this inode even when root cannot traverse
    # the caller's FUSE mount. The GUI keeps access to the image via image_fd.
    executable = root / "usr/bin/mknk-bios-update"
    try:
        gui = sealed_gui(executable)
        os.execve(gui, ["mknk-bios-update", *sys.argv[1:]], env)
    except OSError as exc:
        sys.exit(f"ポータブル版の GUI を起動できません。{exc.strerror}")


if __name__ == "__main__":
    main()
