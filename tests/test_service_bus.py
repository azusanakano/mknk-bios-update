"""Round trip through the actual system service on a private bus, including the CAB FD."""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_engine import Machine


@unittest.skipUnless(sys.platform == "linux", "Unix-FD system D-Bus transport")
class ServiceBusTest(unittest.TestCase):
    def test_authorization_returns_reviewed_bytes_and_records_receipt(self):
        self.exercise_receipt_reporting(switch_user=False)

    def test_only_original_connection_can_report_after_session_switch(self):
        self.exercise_receipt_reporting(switch_user=True)

    def test_declining_an_unsent_permit_allows_a_new_approval_in_the_same_boot(self):
        self.exercise_receipt_reporting(switch_user=False, decline=True)

    def test_definite_rejection_can_only_be_reported_by_original_connection(self):
        self.exercise_receipt_reporting(switch_user=True, reject=True)

    def test_fd_duplication_failure_leaves_no_permission_or_claim(self):
        self.exercise_receipt_reporting(switch_user=False, exhaust_fds=True)

    def test_busy_status_queue_reserves_capacity_for_rejection(self):
        self.exercise_receipt_reporting(switch_user=True, reject=True, busy=True)

    def test_busy_status_queue_reserves_capacity_for_decline(self):
        self.exercise_receipt_reporting(switch_user=False, decline=True, busy=True)

    def exercise_receipt_reporting(self, *, switch_user, decline=False, reject=False, exhaust_fds=False, busy=False):
        import fcntl
        from gi.repository import Gio, GLib
        from engine import Engine
        from journal import Conflict, Journal
        from service import NAME, OBJECT, Service

        payload = b"local integration fixture"

        class Fixture(Machine):
            session_active = True
            marker = None

            def actor(self, sender):
                if not self.session_active:
                    raise Conflict("This logind session is now inactive")
                return super().actor(sender)

            def cabinet(self):
                return os.fdopen(os.memfd_create("test-cab", os.MFD_ALLOW_SEALING), "w+b")

            @contextmanager
            def claim(self, plan):
                self.marker = plan["id"]
                yield

            def release_claim(self, plan):
                if self.marker != plan["id"]:
                    raise Conflict("Wrong marker")
                self.marker = None

            def worker(self, mode, guid, cabinet=None):
                view = super().worker(mode, guid, cabinet)
                if mode == "prepare":
                    cabinet.write(payload)
                    cabinet.flush()
                    seals = fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
                    fcntl.fcntl(cabinet.fileno(), fcntl.F_ADD_SEALS, seals)
                view["checksum"] = hashlib.sha256(payload).hexdigest()
                return view

        with tempfile.TemporaryDirectory() as temp:
            private = Gio.TestDBus.new(Gio.TestDBusFlags.NONE)
            private.up()
            flags = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
            address = private.get_bus_address()
            server = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
            client = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
            other = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
            engine = Engine(Journal(Path(temp) / "journal"), Fixture())
            xml = Path(__file__).resolve().parents[1] / "data" / (NAME + ".xml")
            service = Service(server, engine, xml.read_text(encoding="utf-8"))
            loop = GLib.MainLoop()
            thread = threading.Thread(target=loop.run, daemon=True)
            thread.start()
            try:
                def call(method, sig=None, *args, connection=client):
                    params = GLib.Variant(sig, args) if sig else None
                    reply = connection.call_sync(server.get_unique_name(), OBJECT, NAME, method, params, None,
                                                 Gio.DBusCallFlags.NONE, 15000, None)
                    values = reply.unpack()
                    return json.loads(values[0]) if values else None

                self.assertEqual(call("Status")["current"], "1.20")
                review = call("Prepare", "(s)", call("Check")["token"])
                self.assertEqual(review["state"], "review")

                def authorize(plan):
                    received, handles = client.call_with_unix_fd_list_sync(
                        server.get_unique_name(), OBJECT, NAME, "Authorize", GLib.Variant("(s)", (plan,)),
                        GLib.VariantType.new("(sssh)"), Gio.DBusCallFlags.NONE, 15000, None, None)
                    operation, owner, device, index = received.unpack()
                    self.assertEqual((owner, device, index), (":1.6", "a" * 40, 0))
                    with os.fdopen(handles.get(index), "rb") as sealed:
                        self.assertEqual(sealed.read(), payload)
                        self.assertTrue(fcntl.fcntl(sealed.fileno(), fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE)
                    return operation

                if exhaust_fds:
                    with patch.object(Gio.UnixFDList, "append", side_effect=OSError(errno.EMFILE, "fixture FD limit")):
                        with self.assertRaises(GLib.Error) as failure:
                            authorize(review["plan"])
                    self.assertEqual(Gio.DBusError.get_remote_error(failure.exception), NAME + ".Unavailable")
                    self.assertIsNone(engine.db.active())
                    self.assertIsNone(engine.platform.marker)
                    review = call("Prepare", "(s)", call("Check")["token"])

                operation = authorize(review["plan"])

                @contextmanager
                def busy_status_queue():
                    if not busy:
                        yield
                        return
                    release = threading.Event()
                    drained = threading.Event()
                    remaining = 16
                    dispatch = service.dispatch

                    def wait_on_status(sender, method, args, interactive):
                        if method == "Status" and not release.wait(timeout=12):
                            raise Conflict("Status fixture did not release")
                        return dispatch(sender, method, args, interactive)

                    def status_done(connection, result, _):
                        nonlocal remaining
                        try:
                            connection.call_finish(result)
                        except GLib.Error:
                            pass
                        finally:
                            remaining -= 1
                            if remaining == 0:
                                drained.set()

                    with patch.object(service, "dispatch", wait_on_status):
                        try:
                            for _ in range(16):
                                client.call(server.get_unique_name(), OBJECT, NAME, "Status", None, None,
                                            Gio.DBusCallFlags.NONE, 15000, None, status_done, None)
                            with self.assertRaises(GLib.Error) as failure:
                                call("Status")
                            self.assertEqual(Gio.DBusError.get_remote_error(failure.exception), NAME + ".Busy")
                            yield
                        finally:
                            release.set()
                            self.assertTrue(drained.wait(timeout=8), "queued Status fixture did not drain")

                if reject:
                    engine.platform.session_active = False
                    with busy_status_queue():
                        with self.assertRaises(GLib.Error):
                            call("ReportRejection", "(s)", operation, connection=other)
                        self.assertEqual(engine.db.active()["receipt"], "unknown")
                        self.assertEqual(call("ReportRejection", "(s)", operation), {"recorded": True})
                        self.assertEqual(engine.db.active()["receipt"], "rejected")
                    with self.assertRaises(GLib.Error):
                        call("Status")
                    engine.platform.session_active = True
                    self.assertTrue(call("Status")["can_check"])
                    self.assertIsNone(engine.db.active())
                    self.assertIsNone(engine.platform.marker)
                    return
                if decline:
                    with busy_status_queue():
                        with self.assertRaises(GLib.Error):
                            call("DeclineAuthorization", "(s)", operation, connection=other)
                        self.assertEqual(engine.db.active()["id"], operation)
                        self.assertEqual(engine.platform.marker, operation)
                        call("DeclineAuthorization", "(s)", operation)
                        self.assertIsNone(engine.db.active())
                        self.assertIsNone(engine.platform.marker)
                    review = call("Prepare", "(s)", call("Check")["token"])
                    operation = authorize(review["plan"])
                    call("Report", "(sb)", operation, False)
                    with self.assertRaises(GLib.Error):
                        call("DeclineAuthorization", "(s)", operation)
                    self.assertEqual(engine.platform.marker, operation)
                if switch_user:
                    request = engine.db.power(operation, client.get_unique_name(), engine.platform.bus_id, "boot-1")
                    engine.platform.session_active = False
                    with self.assertRaises(GLib.Error):
                        call("Report", "(sb)", operation, True, connection=other)
                    with self.assertRaises(GLib.Error):
                        call("ReplyPower", "(sb)", request, True, connection=other)
                    self.assertEqual(engine.db.active()["receipt"], "unknown")
                    self.assertEqual(engine.db.active()["power_id"], request)
                    call("ReplyPower", "(sb)", request, True)
                    self.assertIsNone(engine.db.active()["power_id"])
                reported = call("Report", "(sb)", operation, True)
                if switch_user:
                    self.assertEqual(reported, {"recorded": True})
                    with self.assertRaises(GLib.Error):
                        call("Status")
                else:
                    self.assertEqual(reported["state"], "issuing")
                self.assertEqual(engine.db.active()["receipt"], "accepted")
                with self.assertRaises(GLib.Error):
                    call("Authorize", "(s)", review["plan"])
            finally:
                loop.quit()
                thread.join(timeout=4)
                service.close()
                other.close_sync(None)
                client.close_sync(None)
                server.close_sync(None)
                private.down()
