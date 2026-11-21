"""Run a built AppImage as an ordinary user on an isolated X11/AT-SPI desktop."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

import gi

gi.require_version("Atspi", "2.0")
from gi.repository import Atspi, GLib


def accessible_children(node):
    for index in range(node.get_child_count()):
        child = node.get_child_at_index(index)
        if child is not None:
            yield child


def controls(node):
    result = {}
    stack = [node]
    while stack:
        child = stack.pop()
        name = child.get_name()
        if name:
            result.setdefault(name, child)
        stack.extend(accessible_children(child))
    return result


def wait_window(process, action, timeout=100):
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"AppImage exited before showing the window ({process.returncode})")
        while GLib.MainContext.default().iteration(False):
            pass
        for app in accessible_children(Atspi.get_desktop(0)):
            try:
                visible = controls(app)
                if "BIOS 更新" in visible:
                    last = list(visible)
                    if action in visible:
                        return app.get_process_id(), visible
            except GLib.Error:
                continue
        time.sleep(0.2)
    raise RuntimeError(f"Window did not expose {action!r}. Available labels: {last}")


def main(image, extract, status_only):
    if os.getuid() == 0:
        raise RuntimeError("Run as a desktop user")
    if not os.environ.get("DISPLAY") or not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        raise RuntimeError("Run inside an isolated X11 and D-Bus session")
    with tempfile.TemporaryDirectory(prefix="BIOS copy ") as work:
        copied = Path(work) / "BIOS 更新.AppImage"
        shutil.copyfile(image, copied)
        copied.chmod(0o700)
        args = [str(copied)]
        if extract:
            args.append("--appimage-extract-and-run")
        if status_only:
            args.append("--status-only")
        env = dict(os.environ, GTK_A11Y="atspi", GDK_BACKEND="x11", GSK_RENDERER="cairo")
        process = subprocess.Popen(args, cwd="/", env=env)
        pid = None
        try:
            primary = "通常モードで開き直す" if status_only else "更新情報を確認"
            pid, labels = wait_window(process, primary)
            proc = Path("/proc") / str(pid)
            assert "memfd:mknk-bios-update" in os.readlink(proc / "exe")
            assert "/usr/lib/gui/libgtk-4.so" in (proc / "maps").read_text()
            for filename, prefix in [("product_name", "機種"), ("bios_version", "現在の BIOS")]:
                field = Path("/sys/class/dmi/id") / filename
                if field.exists() and os.access(field, os.R_OK):
                    value = field.read_text().strip()
                    assert any(key.startswith(prefix) and value in key for key in labels), (field, labels.keys())
            assert "状態を再確認" in labels
            if status_only:
                assert labels[primary].do_action(0)
                pid, _ = wait_window(process, "更新情報を確認")
            print(f"Copied image, native GTK window, model, BIOS version and next action OK (extract={extract})")
        finally:
            if pid and process.poll() is None:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                process.terminate()
            process.wait(timeout=30)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--extract-and-run", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()
    main(args.image.resolve(strict=True), args.extract_and_run, args.status_only)
