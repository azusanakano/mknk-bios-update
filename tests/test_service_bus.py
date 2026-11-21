"""Round trip through the actual system service on a private bus, including the CAB FD."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from test_engine import Machine


@unittest.skipUnless(sys.platform == "linux", "Unix-FD system D-Bus transport")
class ServiceBusTest(unittest.TestCase):
    def test_authorization_returns_reviewed_bytes_and_records_receipt(self):
        import fcntl
        from gi.repository import Gio, GLib
        from engine import Engine
        from journal import Journal
        from service import NAME, OBJECT, Service

        payload = b"local integration fixture"

        class Fixture(Machine):
            def cabinet(self):
                return os.fdopen(os.memfd_create("test-cab", os.MFD_ALLOW_SEALING), "w+b")

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
            engine = Engine(Journal(Path(temp) / "journal"), Fixture())
            xml = Path(__file__).resolve().parents[1] / "data" / (NAME + ".xml")
            service = Service(server, engine, xml.read_text(encoding="utf-8"))
            loop = GLib.MainLoop()
            thread = threading.Thread(target=loop.run, daemon=True)
            thread.start()
            try:
                def call(method, sig=None, *args):
                    params = GLib.Variant(sig, args) if sig else None
                    reply = client.call_sync(server.get_unique_name(), OBJECT, NAME, method, params, None,
                                             Gio.DBusCallFlags.NONE, 15000, None)
                    return json.loads(reply.unpack()[0])

                self.assertEqual(call("Status")["current"], "1.20")
                review = call("Prepare", "(s)", call("Check")["token"])
                self.assertEqual(review["state"], "review")
                received, handles = client.call_with_unix_fd_list_sync(
                    server.get_unique_name(), OBJECT, NAME, "Authorize", GLib.Variant("(s)", (review["plan"],)),
                    GLib.VariantType.new("(sssh)"), Gio.DBusCallFlags.NONE, 15000, None, None)
                operation, owner, device, index = received.unpack()
                self.assertEqual((owner, device, index), (":1.6", "a" * 40, 0))
                with os.fdopen(handles.get(index), "rb") as sealed:
                    self.assertEqual(sealed.read(), payload)
                    self.assertTrue(fcntl.fcntl(sealed.fileno(), fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE)
                self.assertEqual(call("Report", "(sb)", operation, True)["state"], "issuing")
                with self.assertRaises(GLib.Error):
                    call("Authorize", "(s)", review["plan"])
            finally:
                loop.quit()
                thread.join(timeout=4)
                if service.timer:
                    GLib.source_remove(service.timer)
                service.pool.shutdown()
                server.unregister_object(service.registration)
                client.close_sync(None)
                server.close_sync(None)
                private.down()
