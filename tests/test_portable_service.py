"""The portable transport on an isolated message bus, with no firmware or power operations."""
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import select
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


if sys.platform == "linux":
    import fcntl
    from dataclasses import replace
    from gi.repository import Gio, GLib
    repo = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(repo / "backend"), str(repo)]
    from engine import Engine
    from journal import Conflict, Journal
    from platform_linux import DBUS, LOGIN, Platform
    from portable_service import NAME, SEALS, PeerServer, PortablePlatform, open_verified_gui, pkexec_uid
    from portable.launcher import sealed_gui
    from service import machine_state


def gui_fixture(address):
    from gi.repository import Gio, GLib
    client = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
    system = Gio.DBusConnection.new_for_address_sync(
        address, client | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
    print(system.get_unique_name(), flush=True)
    peer = Gio.DBusConnection.new_for_address_sync(input(), client, None, None)
    print("connected", flush=True)
    name = "io.github.mknk.BiosUpdate1"
    path = "/io/github/mknk/BiosUpdate1"
    for line in sys.stdin:
        command = line.strip()
        if command == "status":
            reply = peer.call_sync(None, path, name, "Status", None, None, 0, 5000, None)
            print(reply.unpack()[0], flush=True)
        elif command == "fd":
            reply, handles = peer.call_with_unix_fd_list_sync(
                None, path, name, "Authorize", GLib.Variant("(s)", ("reviewed",)), None, 0, 5000, None, None)
            plan, owner, device, index = reply.unpack()
            with os.fdopen(handles.get(index), "rb") as stream:
                print(json.dumps([plan, owner, device, stream.read().decode(),
                                  fcntl.fcntl(stream.fileno(), fcntl.F_GET_SEALS)]), flush=True)
        elif command == "watch":
            loop = GLib.MainLoop()
            def changed(*unused):
                print("changed", flush=True)
                loop.quit()
            subscription = peer.signal_subscribe(None, name, "Changed", path, None, 0, changed)
            print("watching", flush=True)
            loop.run()
            peer.signal_unsubscribe(subscription)
        elif command == "close-owner":
            system.close_sync(None)
            print("closed", flush=True)
        elif command == "close-peer":
            peer.close_sync(None)
            print("closed", flush=True)


class PortableViewTest(unittest.TestCase):
    def test_indirect_session_explains_how_to_reopen_the_appimage(self):
        from test_engine import Machine
        from engine import Engine
        from journal import Journal
        platform = Machine()
        platform.portable = True
        with tempfile.TemporaryDirectory() as temp:
            engine = Engine(Journal(Path(temp) / "history"), platform)
            view = engine.status(platform.actor(":2.0"))
        self.assertFalse(view["can_check"])
        self.assertIn("同じ AppImage を開き直してください", view["detail"])
        self.assertNotIn("ランチャー", view["detail"])


@unittest.skipUnless(sys.platform == "linux", "Linux sealed executables and Unix D-Bus credentials")
class PortablePeerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.private = Gio.TestDBus.new(Gio.TestDBusFlags.NONE)
        self.private.up()
        self.addCleanup(self.private.down)
        flags = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
        self.system = Gio.DBusConnection.new_for_address_sync(self.private.get_bus_address(), flags, None, None)
        self.addCleanup(self.system.close_sync, None)

        # Execute the test GUI from a sealed copy of the interpreter, just as
        # AppRun executes the real GUI. Its bus and peer connections share a PID.
        binary = Path(sys.executable)
        with binary.open("rb") as source:
            self.digest = hashlib.file_digest(source, "sha256").hexdigest()
        with os.fdopen(sealed_gui(binary), "rb") as executable:
            self.gui = subprocess.Popen(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--fixture", self.private.get_bus_address()],
                executable=f"/proc/self/fd/{executable.fileno()}", pass_fds=(executable.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.close_gui)
        self.sender = self.line()

        class FixturePlatform(PortablePlatform):
            def call(self, name, path, iface, method, signature=None, args=()):
                if name == LOGIN and method == "GetSessionByPID":
                    return ("/fixture/session",)
                if name == LOGIN and method == "GetAll":
                    return (dict(User=(os.getuid(), "/fixture/user"), Active=True, Remote=False,
                                 Type="wayland", Class="user", Desktop="gnome"),)
                return super().call(name, path, iface, method, signature, args)

        self.platform = FixturePlatform(self.system, self.sender, os.getuid(), self.digest)
        self.addCleanup(self.platform.image.close)

        class FixtureEngine(Engine):
            def status(self, actor):
                return dict(sender=actor.sender, uid=actor.uid, writable=actor.writable, process=actor.process)

            def authorize(self, actor, plan):
                self.required(actor)
                cabinet = os.fdopen(os.memfd_create("fixture-cab", os.MFD_ALLOW_SEALING), "w+b")
                cabinet.write(b"fixture firmware bytes")
                cabinet.flush()
                cabinet.seek(0)
                fcntl.fcntl(cabinet.fileno(), fcntl.F_ADD_SEALS, SEALS)
                return plan, ":1.23", "fixture-device", cabinet

        engine = FixtureEngine(Journal(Path(self.tmp.name) / "history"), self.platform)
        interface = Path(__file__).resolve().parents[1] / "data" / (NAME + ".xml")
        self.server = PeerServer(engine, interface.read_text(encoding="utf-8"))

    def close_gui(self):
        if self.gui.poll() is None:
            self.gui.kill()
        self.gui.communicate(timeout=5)

    def line(self):
        self.assertTrue(select.select([self.gui.stdout], [], [], 10)[0], "GUI fixture did not reply")
        value = self.gui.stdout.readline()
        if not value:
            self.fail(self.gui.communicate(timeout=5)[1])
        return value.strip()

    def command(self, value):
        self.gui.stdin.write(value + "\n")
        self.gui.stdin.flush()
        return self.line()

    def listen(self, timeout_ms=10000):
        addresses = Queue()
        self.thread = threading.Thread(target=self.server.run, args=(addresses.put, timeout_ms), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        return addresses.get(timeout=5)

    def stop_server(self):
        if self.thread.is_alive():
            self.server.stop()
            self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def test_only_pinned_process_receives_peer_calls_and_cab_fd(self):
        self.platform.call(DBUS, "/org/freedesktop/DBus", DBUS, "RequestName", "(su)", ("org.freedesktop.UPower", 4))
        address = self.listen()
        # The test process is a different PID under the same real UID.
        with self.assertRaises(GLib.Error):
            Gio.DBusConnection.new_for_address_sync(
                address, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT, None, None)
        self.assertEqual(self.command(address), "connected")
        view = json.loads(self.command("status"))
        self.assertEqual(view["sender"], self.sender)
        self.assertEqual(view["uid"], os.getuid())
        self.assertTrue(view["writable"])
        self.assertEqual(view["process"], f"{self.gui.pid}:{self.platform.process.start}")
        self.assertEqual(self.command("watch"), "watching")
        self.system.emit_signal(None, "/org/freedesktop/UPower", DBUS + ".Properties", "PropertiesChanged",
                                GLib.Variant("(sa{sv}as)", ("org.freedesktop.UPower", {}, [])))
        self.assertEqual(self.line(), "changed")
        received = json.loads(self.command("fd"))
        self.assertEqual(received[:4], ["reviewed", ":1.23", "fixture-device", "fixture firmware bytes"])
        self.assertEqual(received[4] & SEALS, SEALS)
        self.assertEqual(self.command("close-peer"), "closed")
        self.thread.join(timeout=4)
        self.assertFalse(self.thread.is_alive(), "helper outlived its peer")
        with self.assertRaises(Conflict):
            self.platform.actor(self.sender)

    def test_system_owner_loss_stops_helper_with_peer_open(self):
        self.assertEqual(self.command(self.listen()), "connected")
        self.assertTrue(json.loads(self.command("status"))["writable"])
        started, notify_fd = os.pipe()
        self.addCleanup(os.close, started)
        self.addCleanup(os.close, notify_fd)
        command = [sys.executable, "-I", "-c", "import os,sys,signal; os.write(int(sys.argv[1]), b'x'); signal.pause()",
                   str(notify_fd)]
        results = Queue()
        worker = threading.Thread(target=lambda: results.put(
            self.platform.execute_worker(command, b"", pass_fds=(notify_fd,))), daemon=True)
        worker.start()
        self.assertTrue(select.select([started], [], [], 5)[0], "worker did not start")
        self.assertEqual(self.command("close-owner"), "closed")
        self.thread.join(timeout=4)
        self.assertFalse(self.thread.is_alive(), "helper outlived its system-bus owner")
        self.assertIsNone(self.gui.poll(), "GUI fixture must remain alive during the check")
        self.assertLess(results.get(timeout=3).returncode, 0)
        with self.assertRaises(Conflict):
            self.platform.execute_worker(command, b"")

    def test_unclaimed_helper_expires(self):
        self.listen(timeout_ms=80)
        self.thread.join(timeout=4)
        self.assertFalse(self.thread.is_alive())
        self.assertIsNone(self.server.service)

    def test_uid_hash_process_start_and_seals_are_independently_required(self):
        with self.assertRaises(Conflict):
            PortablePlatform(self.system, self.sender, os.getuid() + 1, self.digest)
        with self.assertRaises(Conflict):
            PortablePlatform(self.system, self.sender, os.getuid(), "0" * 64)
        with self.assertRaises(Conflict):
            self.platform.verify_process(self.sender, replace(self.platform.process, start="0"))
        with self.assertRaises(Conflict):
            self.platform.verify_process(":1.56789", self.platform.process)
        with self.assertRaises(Conflict):
            open_verified_gui(Path(sys.executable), self.digest)

    def test_installed_service_name_blocks_second_backend(self):
        self.platform.call(DBUS, "/org/freedesktop/DBus", DBUS, "RequestName", "(su)", (NAME, 4))
        with self.assertRaisesRegex(Conflict, "インストール済み"):
            self.platform.check_installed_service()


@unittest.skipUnless(sys.platform == "linux", "Linux worker accounts and directory locks")
class PortablePlatformTest(unittest.TestCase):
    def test_directory_is_locked_across_instances_and_released_on_exit(self):
        from types import SimpleNamespace
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        with tempfile.TemporaryDirectory() as temp, patch("service.STATE", Path(temp)), patch(
                "service.os.fstat", return_value=SimpleNamespace(st_uid=0, st_mode=0o40700)):
            with machine_state():
                with self.assertRaisesRegex(Conflict, "別の"):
                    with machine_state():
                        self.fail("two backends acquired the same directory")
            with machine_state() as state:
                self.assertEqual(state, Path(temp))

    def test_only_pkexec_numeric_nonroot_uid_is_accepted(self):
        self.assertEqual(pkexec_uid("1000"), 1000)
        for value in (None, "", "0", "-1", " 1000", "１", str(2**32 - 1)):
            with self.subTest(value=value), self.assertRaises(Conflict):
                pkexec_uid(value)

    def test_worker_fallback_and_private_profile_snapshot(self):
        import pwd
        from types import SimpleNamespace
        nobody = pwd.getpwnam("nobody")
        with patch("platform_linux.pwd.getpwnam", side_effect=[KeyError(), nobody]), patch.object(
                Platform, "call", return_value=("fixture-bus",)):
            platform = Platform(None, portable=True)
        result = SimpleNamespace(returncode=0, stdout=b'{"state":"hold"}')
        profile = {"dmi": {"product_name": "fixture"}}
        with patch("platform_linux.fw.read_settings", return_value=profile), patch(
                "platform_linux.read_trust_policy", return_value="0"), patch(
                "platform_linux.subprocess.run", return_value=result) as run:
            self.assertEqual(platform.worker("check", "g"), {"state": "hold"})
        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-S"])
        self.assertTrue(argv[3].endswith("/worker.py"))
        self.assertEqual((options["user"], options["group"], options["extra_groups"]),
                         (nobody.pw_uid, nobody.pw_gid, []))
        self.assertEqual(set(options["env"]), {"PATH", "LANG", "HOME", "MKNK_FWUPD_ONLY_PQ",
                                                "LD_LIBRARY_PATH", "GI_TYPELIB_PATH"})
        self.assertEqual(json.loads(options["input"])["profile"], profile)
        with patch("platform_linux.fw.read_settings", side_effect=[profile, {}]), patch(
                "platform_linux.read_trust_policy", return_value="0"), patch(
                "platform_linux.subprocess.run", return_value=result), self.assertRaises(Conflict):
            platform.worker("check", "g")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        gui_fixture(sys.argv[2])
    else:
        unittest.main()
