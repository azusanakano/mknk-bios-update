"""Exercise the smoke runner against two real GTK windows on a private display."""
from contextlib import contextmanager
from importlib.util import find_spec
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve()
ACTION = "通常モードで開き直す"


class SmokeAppImageTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux process sessions")
    def test_matching_window_is_clicked_and_stopped_only_for_launched_session(self):
        if not all(find_spec(module) for module in ("gi", "Xlib")) or not all(
            shutil.which(tool) for tool in ("xvfb-run", "dbus-run-session", "xdotool")
        ):
            self.skipTest("requires PyGObject, Python Xlib, Xvfb, D-Bus, and xdotool")
        import gi
        try:
            gi.require_version("Gtk", "4.0")
            gi.require_version("Atspi", "2.0")
        except ValueError as error:
            self.skipTest(str(error))

        subprocess.run(
            ["xvfb-run", "-a", "dbus-run-session", sys.executable, "-B", str(SCRIPT), "verify"],
            check=True, timeout=70,
            env=dict(os.environ, GTK_A11Y="atspi", GDK_BACKEND="x11", GSK_RENDERER="cairo"),
        )


def window(marker):
    import gi

    gi.require_version("Gtk", "4.0")
    from gi.repository import Gio, Gtk

    app = Gtk.Application(application_id="io.github.mknk.SmokeFixture", flags=Gio.ApplicationFlags.NON_UNIQUE)

    def activate(app):
        frame = Gtk.ApplicationWindow(application=app, title="BIOS 更新", default_width=320, default_height=110)
        button = Gtk.Button(label=ACTION)
        button.connect("clicked", lambda _button: marker.touch())
        frame.set_child(button)
        frame.present()

    app.connect("activate", activate)
    return app.run([])


@contextmanager
def fixture(mode, marker):
    process = subprocess.Popen([sys.executable, "-B", str(SCRIPT), mode, str(marker)], start_new_session=True)
    try:
        yield process
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def verify():
    import smoke_appimage as smoke

    with tempfile.TemporaryDirectory() as work:
        decoy_marker = Path(work) / "decoy-clicked"
        owned_marker = Path(work) / "owned-clicked"
        with fixture("window", decoy_marker) as decoy:
            decoy_pid, decoy_labels = smoke.wait_window(decoy, ACTION, timeout=15)
            assert decoy_pid == decoy.pid
            with fixture("launcher", owned_marker) as launched:
                pid, labels = smoke.wait_window(launched, ACTION, timeout=15)
                assert pid != decoy.pid, "Smoke runner selected the pre-existing BIOS window"
                assert pid != launched.pid, "This fixture puts the owned GTK window in a runtime child"
                with unittest.TestCase().assertRaises(RuntimeError):
                    smoke.click_button(launched, decoy.pid, decoy_labels[ACTION])
                button = labels[ACTION]
                # GTK versions that implement AT-SPI actions must still test the X11 fallback.
                without_action = SimpleNamespace(get_n_actions=lambda: 0, get_extents=button.get_extents,
                                                 get_name=button.get_name)
                smoke.click_button(launched, pid, without_action)
                deadline = time.monotonic() + 3
                while not owned_marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert owned_marker.exists() and not decoy_marker.exists(), "Only the launched window may be clicked"
                child = os.pidfd_open(pid)
                try:
                    smoke.stop_app(launched, decoy.pid)
                    assert select.select([child], [], [], 5)[0], "Cleanup left a launched GUI running"
                    assert decoy.poll() is None, "Cleanup stopped the pre-existing BIOS window"
                finally:
                    os.close(child)


if __name__ == "__main__":
    if sys.argv[1:] == ["verify"]:
        verify()
    elif len(sys.argv) == 3 and sys.argv[1] == "window":
        sys.exit(window(Path(sys.argv[2])))
    elif len(sys.argv) == 3 and sys.argv[1] == "launcher":
        # The first accessibility scan must see the already-open window before this child opens.
        time.sleep(1)
        sys.exit(subprocess.call([sys.executable, "-B", str(SCRIPT), "window", sys.argv[2]]))
    else:
        unittest.main()
