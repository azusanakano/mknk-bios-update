"""The portable transport on an isolated message bus, with no firmware or power operations."""
from dataclasses import replace
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
    from gi.repository import Gio, GLib
    repo = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(repo / "backend"), str(repo)]
    from engine import Engine
    from firmware_api import fw
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
    def test_user_scope_prompts_for_explicit_access_before_catalog_check(self):
        from test_engine import Machine
        from engine import Engine
        from journal import Journal
        platform = Machine()
        platform.portable = True
        actor = replace(platform.actor(":2.0"), can_open_plan=True)
        with tempfile.TemporaryDirectory() as temp:
            view = Engine(Journal(Path(temp) / "history"), platform).status(actor)
        self.assertTrue(view.get("can_open_plan"))
        self.assertFalse(view["can_check"])

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
        # Starting a sealed Python/GIO process can take much longer than a
        # response on its established connection, particularly in a VM.
        self.sender = self.line(timeout=float(os.environ.get("MKNK_TEST_GUI_START_TIMEOUT", "60")))

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

            def authorize(self, actor, plan, *, prepare_reply):
                self.required(actor)
                cabinet = os.fdopen(os.memfd_create("fixture-cab", os.MFD_ALLOW_SEALING), "w+b")
                cabinet.write(b"fixture firmware bytes")
                cabinet.flush()
                cabinet.seek(0)
                fcntl.fcntl(cabinet.fileno(), fcntl.F_ADD_SEALS, SEALS)
                with cabinet:
                    return prepare_reply(plan, ":1.23", "fixture-device", cabinet)

        engine = FixtureEngine(Journal(Path(self.tmp.name) / "history"), self.platform)
        interface = Path(__file__).resolve().parents[1] / "data" / (NAME + ".xml")
        self.server = PeerServer(engine, interface.read_text(encoding="utf-8"))

    def close_gui(self):
        if self.gui.poll() is None:
            self.gui.kill()
        self.gui.communicate(timeout=5)

    def line(self, *, timeout=10):
        self.assertTrue(select.select([self.gui.stdout], [], [], timeout)[0], "GUI fixture did not reply")
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
    def test_release_approval_checks_the_original_connection_with_admin_policy(self):
        from test_engine import Machine

        platform = object.__new__(Platform)
        caller = Machine().actor(":1.2")

        for portable, action in (
                (False, "io.github.mknk.BiosUpdate1.release-approval"),
                (True, "org.freedesktop.policykit.exec")):
            platform.portable = portable
            for allowed in (True, False):
                response = GLib.Variant("((bba{ss}))", ((allowed, not allowed, {}),))
                with self.subTest(portable=portable, allowed=allowed), patch.object(
                        platform, "bus", create=True) as bus:
                    bus.call_sync.return_value = response
                    if allowed:
                        platform.require_administrator(caller)
                    else:
                        with self.assertRaises(Conflict):
                            platform.require_administrator(caller)
                    _, _, _, method, params, signature, *_ = bus.call_sync.call_args.args
                    subject, request, details, flags, _ = params.unpack()
                    self.assertEqual(method, "CheckAuthorization")
                    self.assertEqual(signature.dup_string(), "((bba{ss}))")
                    self.assertEqual(subject, ("system-bus-name", {"name": caller.sender}))
                    self.assertEqual((request, flags), (action, 1))
                    self.assertEqual(bool(details.get("polkit.message")), portable)

    def test_unstarted_metadata_worker_releases_fence_but_ambiguous_worker_holds_it(self):
        import pwd

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            boot = root / "boot"
            boot.write_text("same-boot", encoding="ascii")
            journal = Journal(root / "state")
            platform = object.__new__(Platform)
            platform.portable = False
            platform.bus_id = "bus"
            platform.worker_user = pwd.getpwnam("nobody")
            platform.cabinet = tempfile.TemporaryFile
            platform.confirm_owner = lambda owner: None
            platform.call = lambda *args: (os.getpid(),)
            result = dict(state="metadata", signed_timestamp=100, catalog_sha256="a" * 64,
                          daemon_owner=":1.8", remote_id="stable", remote_fingerprint="remote",
                          settings_fingerprint="settings")

            run_worker = platform.run_worker

            def worker(mode, *args, **kwargs):
                return result if mode == "metadata" else run_worker(mode, *args, **kwargs)

            with patch.object(platform, "run_worker", side_effect=worker), patch.object(fw, "BOOT_ID", boot), patch(
                    "platform_linux.read_trust_policy", return_value="0"):
                with patch("platform_linux.subprocess.Popen", side_effect=OSError("no process slots")):
                    with self.assertRaises((Conflict, OSError)):
                        platform.refresh("guid", journal, lambda: None)
                platform.metadata_clear(journal)
                self.assertFalse(journal.setting("metadata-request"))

                with patch.object(platform, "execute_worker", side_effect=Conflict("reply after start is unknown")):
                    with self.assertRaises(Conflict):
                        platform.refresh("guid", journal, lambda: None)
                with self.assertRaises(Conflict):
                    platform.metadata_clear(journal)

    def test_stale_metadata_reader_cannot_clear_a_new_request(self):
        from threading import Event, Thread

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            boot = root / "boot"
            boot.write_text("current-boot", encoding="ascii")
            journal = Journal(root / "state")
            journal.setting("metadata-request", dict(boot="old-boot", pid=os.getpid(), start="old"))
            platform = object.__new__(Platform)
            seen_old = Event()
            allow_clear = Event()
            outcomes = []
            lookup = journal.setting
            start = (Path("/proc") / str(os.getpid()) / "stat").read_text().rsplit(")", 1)[1].split()[19]
            new = dict(id="new", boot="current-boot", pid=os.getpid(), start=start)

            def pause_after_read(name, value=None):
                result = lookup(name, value)
                if value is None and result and result["boot"] == "old-boot":
                    seen_old.set()
                    if not allow_clear.wait(3):
                        raise AssertionError("timed out waiting to resume the old reader")
                return result

            def reconcile():
                try:
                    platform.metadata_clear(journal)
                except Exception as exc:
                    outcomes.append(exc)

            with patch.object(journal, "setting", side_effect=pause_after_read), patch.object(fw, "BOOT_ID", boot):
                reader = Thread(target=reconcile)
                reader.start()
                try:
                    self.assertTrue(seen_old.wait(3))
                    Journal(root / "state").setting("metadata-request", new)
                finally:
                    allow_clear.set()
                    reader.join()
            self.assertEqual(lookup("metadata-request"), new)
            self.assertEqual(len(outcomes), 1)
            self.assertIsInstance(outcomes[0], Conflict)

    def test_metadata_worker_reports_definite_not_sent_when_remote_lookup_fails(self):
        import worker

        with patch.object(fw, "read_settings", return_value={}), patch.object(
                worker.catalog, "Session") as session, patch.object(Gio, "bus_get_sync") as bus:
            session.return_value.remote.side_effect = fw.Hold("fixture failure with private details")
            response = worker.import_metadata(dict(owner=":1.2", remote="lvfs", fds=[]))
        bus.assert_not_called()
        self.assertIs(response["terminal"], True)
        self.assertIs(response["ok"], False)
        self.assertNotIn("private", response["detail"])

    def test_portable_profile_change_preserves_the_terminal_import_response(self):
        import pwd

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            boot = root / "boot"
            boot.write_text("same-boot", encoding="ascii")
            journal = Journal(root / "state")
            platform = object.__new__(Platform)
            platform.portable = True
            platform.bus_id = "bus"
            platform.worker_user = pwd.getpwnam("nobody")
            platform.cabinet = tempfile.TemporaryFile
            platform.confirm_owner = lambda owner: None
            platform.call = lambda *args: (os.getpid(),)
            catalog = dict(state="metadata", signed_timestamp=100, catalog_sha256="a" * 64,
                           daemon_owner=":1.8", remote_id="stable", remote_fingerprint="remote",
                           settings_fingerprint="settings")
            run = platform.run_worker

            def worker(mode, *args, **kwargs):
                return catalog if mode == "metadata" else run(mode, *args, **kwargs)

            for changed in ({"version": "changed"}, fw.Hold("configuration cannot be read")):
                with self.subTest(changed=changed), patch.object(platform, "run_worker", side_effect=worker), patch.object(
                        fw, "BOOT_ID", boot), patch.object(fw, "read_settings", side_effect=[{}, changed]), patch(
                        "platform_linux.read_trust_policy", return_value="0"), patch.object(
                        platform, "execute_worker", return_value=subprocess.CompletedProcess(
                            [], 0, b'{"terminal": true, "ok": true}')):
                    with self.assertRaises(Conflict):
                        platform.refresh("guid", journal, lambda: None)
                self.assertFalse(journal.setting("metadata-request"))

    def test_declined_authorization_removes_only_the_matching_marker(self):
        import uuid
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            boot = str(uuid.uuid4())
            boot_file = root / "boot"
            boot_file.write_text(boot, encoding="ascii")
            platform = object.__new__(Platform)
            plan = dict(id=str(uuid.uuid4()), boot=boot)
            real_fstat = os.fstat

            def root_metadata(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)

            with patch.multiple(fw, BOOT_ID=boot_file, LOCK_DIR=root, LEGACY_LOCK_DIR=root / "legacy"):
                with platform.claim(plan):
                    pass
                marker = fw.marker_path()
                entry = marker / "gui-operation"
                with patch("hardware.os.fstat", side_effect=root_metadata):
                    with self.assertRaises(Conflict):
                        platform.release_claim(dict(plan, id=str(uuid.uuid4())))
                    self.assertEqual(entry.read_text(encoding="ascii"), plan["id"])
                    platform.release_claim(plan)
                    self.assertFalse(marker.exists())
                    platform.release_claim(plan)

    def test_failed_marker_write_leaves_no_claim(self):
        import errno

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "request"
            platform = object.__new__(Platform)
            with patch("platform_linux.fw.marker_path", return_value=marker), patch(
                    "platform_linux.os.fchmod", side_effect=OSError(errno.ENOSPC, "disk full")):
                with self.assertRaises(OSError), platform.claim({"id": "fixture"}):
                    self.fail("A marker that could not be written yielded permission to issue")
            self.assertFalse(marker.exists())

    def test_recovered_claim_is_retired_before_its_files_are_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "request"
            marker.mkdir()
            (marker / "gui-operation").write_text("fixture", encoding="ascii")
            with patch("hardware._owns_marker", return_value=True), patch.object(
                    Path, "unlink", side_effect=PermissionError("cleanup interrupted")):
                self.assertTrue(Platform.remove_gui_claim(marker, {"id": "fixture"}, "boot"))
            self.assertFalse(marker.exists())
            self.assertEqual(len(list(Path(temp).iterdir())), 1)

    def test_issue_rollback_releases_claim_but_committed_issue_keeps_it(self):
        import sqlite3
        from contextlib import closing, contextmanager

        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "request"
            journal = Journal(Path(temp) / "state")
            platform = object.__new__(Platform)
            plan = dict(id="fixture", boot="boot", machine="pc")
            transaction = journal.transaction

            @contextmanager
            def failed_commit():
                with transaction() as db:
                    yield db
                    raise sqlite3.OperationalError("simulated failed commit")

            @contextmanager
            def failed_after_commit():
                with transaction() as db:
                    yield db
                raise sqlite3.OperationalError("simulated post-commit failure")

            with patch("platform_linux.fw.marker_path", return_value=marker):
                with closing(sqlite3.connect(journal.path)) as raw:
                    raw.execute("""CREATE TRIGGER broken BEFORE INSERT ON operation
                                   BEGIN SELECT unknown_write_hook(); END""")
                    raw.commit()
                    with self.assertRaises(Conflict), platform.claim(plan):
                        journal.issue(plan, ":1.2", ":1.6", "bus")
                    self.assertFalse(marker.exists())
                    raw.execute("DROP TRIGGER broken")
                    raw.commit()
                with patch.object(journal, "transaction", failed_commit):
                    with self.assertRaises(Conflict), platform.claim(plan):
                        journal.issue(plan, ":1.2", ":1.6", "bus")
                self.assertFalse(marker.exists())
                self.assertIsNone(journal.active())
                with patch.object(journal, "transaction", failed_after_commit):
                    with self.assertRaises(sqlite3.OperationalError), platform.claim(plan):
                        journal.issue(plan, ":1.2", ":1.6", "bus")
                self.assertEqual((marker / "gui-operation").read_text(encoding="ascii"), plan["id"])
                self.assertEqual(journal.active()["id"], plan["id"])

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
                "platform_linux.Platform.execute_worker", return_value=result) as run:
            self.assertEqual(platform.worker("check", "g"), {"state": "hold"})
        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-S"])
        self.assertTrue(argv[3].endswith("/worker.py"))
        self.assertEqual((options["user"], options["group"], options["extra_groups"]),
                         (nobody.pw_uid, nobody.pw_gid, []))
        self.assertEqual(set(options["env"]), {"PATH", "LANG", "HOME", "MKNK_FWUPD_ONLY_PQ",
                                                "LD_LIBRARY_PATH", "GI_TYPELIB_PATH"})
        self.assertEqual(json.loads(run.call_args.args[1])["profile"], profile)
        with patch("platform_linux.fw.read_settings", side_effect=[profile, {}]), patch(
                "platform_linux.read_trust_policy", return_value="0"), patch(
                "platform_linux.Platform.execute_worker", return_value=result), self.assertRaises(Conflict):
            platform.worker("check", "g")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        gui_fixture(sys.argv[2])
    else:
        unittest.main()
