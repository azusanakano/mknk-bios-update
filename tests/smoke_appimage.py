"""Run a built AppImage on isolated X11/AT-SPI with xdotool and Python Xlib."""
import argparse
from contextlib import suppress
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


def belongs_to_launch(process, pid):
    try:
        return os.getsid(pid) == process.pid
    except ProcessLookupError:
        return False


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
                pid = app.get_process_id()
                if not belongs_to_launch(process, pid):
                    continue
                visible = controls(app)
                if "BIOS 更新" in visible:
                    last = list(visible)
                    if action in visible:
                        return pid, visible
            except GLib.Error:
                continue
        time.sleep(0.2)
    raise RuntimeError(f"Window did not expose {action!r}. Available labels: {last}")


def click_button(process, pid, button):
    if not belongs_to_launch(process, pid):
        raise RuntimeError("The BIOS window no longer belongs to this AppImage launch")
    # GTK4 may expose a button without exposing an AT-SPI Action for it.
    # Use its accessible bounds to click the verified X11 window.
    if button.get_n_actions():
        assert button.do_action(0)
        return
    windows = subprocess.check_output(
        ["xdotool", "search", "--all", "--onlyvisible", "--pid", str(pid), "--name", "^BIOS 更新$"], text=True
    ).splitlines()
    if len(windows) != 1:
        raise RuntimeError(f"Expected one visible BIOS window for PID {pid}. Found {windows}")
    rect = button.get_extents(Atspi.CoordType.WINDOW)
    if rect.width <= 0 or rect.height <= 0:
        raise RuntimeError(f"The {button.get_name()} button did not expose its bounds")
    click_x11(process, pid, int(windows[0]), rect.x + rect.width // 2, rect.y + rect.height // 2)


def click_x11(process, pid, window_id, x, y):
    from Xlib import X, Xatom, display
    from Xlib.ext import xtest

    client = display.Display()
    try:
        # Other clients cannot change the window stack or grab the pointer while
        # this connection verifies the target and sends the XTEST events.
        client.grab_server()
        window = client.create_resource_object("window", window_id)
        owner = window.get_full_property(client.intern_atom("_NET_WM_PID"), Xatom.CARDINAL)
        if owner is None or list(owner.value) != [pid] or not belongs_to_launch(process, pid):
            raise RuntimeError("The X11 window no longer belongs to this AppImage launch")
        window.configure(stack_mode=X.Above)
        window.warp_pointer(x, y)
        pointed = client.screen().root.query_pointer().child
        while pointed and pointed != window:
            pointed = pointed.query_pointer().child
        if pointed != window:
            raise RuntimeError("The pointer is outside the launched BIOS window")
        if window.grab_pointer(False, X.ButtonPressMask | X.ButtonReleaseMask, X.GrabModeAsync,
                               X.GrabModeAsync, X.NONE, X.NONE, X.CurrentTime) != X.GrabSuccess:
            raise RuntimeError("The X11 pointer is already grabbed")
        client.ungrab_pointer(X.CurrentTime)
        xtest.fake_input(client, X.ButtonPress, 1)
        xtest.fake_input(client, X.ButtonRelease, 1)
        client.sync()
    finally:
        client.ungrab_server()
        client.close()


def stop_window(process, pid):
    # Hold the process identity while checking its session and sending the signal.
    try:
        pidfd = os.pidfd_open(pid)
        try:
            if belongs_to_launch(process, pid):
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                return True
        finally:
            os.close(pidfd)
    except ProcessLookupError:
        pass
    return False


def stop_app(process, pid):
    if process.poll() is not None:
        return
    # Stopping the GUI first lets the extract-and-run wrapper clean up its files.
    if pid is None or not stop_window(process, pid):
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


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
        # Both the runtime and any AppRun child inherit this private process session.
        process = subprocess.Popen(args, cwd="/", env=env, start_new_session=True)
        pid = None
        try:
            primary = "通常モードで開き直す" if status_only else "更新情報を確認"
            pid, labels = wait_window(process, primary)
            proc = Path("/proc") / str(pid)
            assert "memfd:mknk-bios-update" in os.readlink(proc / "exe")
            assert b"/usr/lib/gui/libgtk-4.so" in (proc / "maps").read_bytes()
            for filename, prefix in [("product_name", "機種"), ("bios_version", "現在の BIOS")]:
                field = Path("/sys/class/dmi/id") / filename
                if field.exists() and os.access(field, os.R_OK):
                    value = field.read_text().strip()
                    assert any(key.startswith(prefix) and value in key for key in labels), (field, labels.keys())
            assert "状態を再確認" in labels
            if status_only:
                click_button(process, pid, labels[primary])
                pid, _ = wait_window(process, "更新情報を確認")
            print(f"Copied image, native GTK window, model, BIOS version and next action OK (extract={extract})")
        finally:
            stop_app(process, pid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--extract-and-run", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()
    main(args.image.resolve(strict=True), args.extract_and_run, args.status_only)
