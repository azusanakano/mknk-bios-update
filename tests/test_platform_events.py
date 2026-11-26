"""Checks of read-only logind conditions and private D-Bus metadata replies."""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))


@unittest.skipUnless(sys.platform == "linux", "GIO and systemd integration")
class PlatformEventsTest(unittest.TestCase):
    def test_power_hardware_service_does_not_query_root_power_permissions(self):
        from engine import Actor
        from journal import Conflict
        from platform_linux import Platform

        actor = Actor(":1.10", 1000, "/session/1", "bus", True, "gnome", "100:200")
        platform = object.__new__(Platform)
        platform.call = Mock(side_effect=[([],), ([],)])
        platform.power_allowed(actor, "reboot")
        self.assertEqual([args.args[3] for args in platform.call.call_args_list], ["ListInhibitors", "ListSessions"])
        platform.call.side_effect = [([("idle:shutdown", "fixture", "save", "block", 1001, 900)],)]
        with self.assertRaisesRegex(Conflict, "終了"):
            platform.power_allowed(actor, "shutdown")

    def test_services_subscribe_to_power_and_volume_changes(self):
        from gi.repository import GLib
        from platform_linux import LOGIN, MANAGER, PROPERTIES
        from service import Service

        bus = Mock()
        interface = (Path(__file__).resolve().parents[1] / "data/io.github.mknk.BiosUpdate1.xml").read_text()
        service = Service(bus, Mock(), interface)
        self.addCleanup(service.close)
        subscriptions = bus.signal_subscribe.call_args_list
        for event in ("SessionNew", "SessionRemoved"):
            self.assertTrue(any(c.args[:4] == (LOGIN, LOGIN + ".Manager", event, MANAGER) for c in subscriptions))
        self.assertTrue(any(c.args[:5] == ("org.freedesktop.UDisks2", PROPERTIES, "PropertiesChanged",
                                          None, "org.freedesktop.UDisks2.Filesystem") for c in subscriptions))
        callbacks = [c.args[-1] for c in subscriptions if c.args[:4] ==
                     (LOGIN, PROPERTIES, "PropertiesChanged", MANAGER)]
        (changed,) = callbacks
        service.observation_changed = Mock()
        for prop in ("PreparingForSleep", "BlockInhibited", "BlockWeakInhibited"):
            changed(None, LOGIN, MANAGER, PROPERTIES, "PropertiesChanged",
                    GLib.Variant("(sa{sv}as)", (LOGIN + ".Manager", {}, [prop])))
        self.assertEqual(service.observation_changed.call_count, 2)

    def test_only_trusted_metadata_bus_denials_finish_the_import(self):
        from gi.repository import Gio, GLib
        from worker import send_metadata

        owner = ":1.9"
        bus = Mock()
        for sender, name, expected in (
                ("org.freedesktop.DBus", "org.freedesktop.DBus.Error.AccessDenied", (True, False)),
                ("org.freedesktop.DBus", "org.freedesktop.DBus.Error.NameHasNoOwner", (True, False)),
                (owner, "org.freedesktop.DBus.Error.AccessDenied", (False, False)),
                (":1.10", "org.freedesktop.fwupd.NothingToDo", (False, False)),
                (owner, "org.freedesktop.fwupd.NothingToDo", (True, True)),
                ("org.freedesktop.DBus", "org.freedesktop.DBus.Error.NoReply", (False, False)),
        ):
            with self.subTest(sender=sender, name=name):
                result = Gio.DBusMessage.new()
                result.set_message_type(Gio.DBusMessageType.ERROR)
                result.set_sender(sender)
                result.set_error_name(name)
                bus.send_message_with_reply_sync.return_value = (result, 1)
                data = send_metadata(bus, owner, "lvfs", Gio.UnixFDList.new())
                self.assertEqual((data["terminal"], data["ok"]), expected)
                message = bus.send_message_with_reply_sync.call_args.args[0]
                self.assertEqual((message.get_destination(), message.get_member()), (owner, "UpdateMetadata"))
                self.assertEqual(message.get_body().unpack(), ("lvfs", 0, 1))
        bus.send_message_with_reply_sync.side_effect = GLib.Error("no transport reply")
        data = send_metadata(bus, owner, "lvfs", Gio.UnixFDList.new())
        self.assertFalse(data["terminal"])

    def test_missing_destination_has_a_terminal_reply_from_a_real_private_bus(self):
        import tempfile
        from gi.repository import Gio
        from worker import send_metadata

        private = Gio.TestDBus.new(Gio.TestDBusFlags.NONE)
        private.up()
        self.addCleanup(private.down)
        flags = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
        bus = Gio.DBusConnection.new_for_address_sync(private.get_bus_address(), flags, None, None)
        self.addCleanup(bus.close_sync, None)
        files = Gio.UnixFDList.new()
        with tempfile.TemporaryFile() as payload, tempfile.TemporaryFile() as signature:
            files.append(payload.fileno())
            files.append(signature.fileno())
            result = send_metadata(bus, ":1.123456", "lvfs", files)
        self.assertTrue(result["terminal"])
        self.assertFalse(result["ok"])
