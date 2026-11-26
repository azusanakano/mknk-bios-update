"""Session and administrator gate with fixture logind and polkit replies."""
from dataclasses import replace
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


if sys.platform == "linux":
    from gi.repository import Gio, GLib
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from journal import Conflict
    from platform_linux import BusProcess, DBUS, DBUS_PATH, LOGIN, MANAGER, POLKIT, PROPERTIES, Platform
    from service import Service

    SESSION = MANAGER + "/session/_32"
    OTHER_SESSION = MANAGER + "/session/_33"
    USER = MANAGER + "/user/_1000"
    SEAT = MANAGER + "/seat/seat0"
    OWNER = ":1.8"
    GUI = ":1.20"
    SECOND_GUI = ":1.21"
    OTHER_APP = ":1.22"

    class ScopedPlatform(Platform):
        def __init__(self):
            account = SimpleNamespace(pw_uid=65123, pw_gid=65123)
            with patch("platform_linux.pwd.getpwnam", return_value=account):
                super().__init__(Mock())
            self.processes = {GUI: BusProcess(1000, 302, "921"), SECOND_GUI: BusProcess(1000, 302, "921"),
                              OTHER_APP: BusProcess(1000, 303, "922")}
            self.session = dict(User=(1000, USER), Active=True, Remote=False, Type="wayland", Class="user",
                                Desktop="ubuntu", Seat=("seat0", SEAT), TimestampMonotonic=728, LockedHint=False)
            self.user = dict(UID=1000, Sessions=[("2", SESSION)], Display=("2", SESSION))
            self.seat = dict(ActiveSession=("2", SESSION))
            self.direct = False
            self.real_owner = True

        def call(self, name, path, iface, method, signature=None, args=()):
            if (name, method) == (DBUS, "GetId"):
                return ("fixture-bus",)
            if (name, method, args) == (DBUS, "GetNameOwner", (LOGIN,)):
                return (OWNER,)
            if (name, method) == (LOGIN, "GetSessionByPID"):
                if self.direct:
                    return (SESSION,)
                raise Gio.DBusError.new_for_dbus_error(LOGIN + ".NoSessionForPID", "fixture user scope")
            if (name, method) == (OWNER, "GetUserByPID"):
                if self.real_owner:
                    return (USER,)
                raise Gio.DBusError.new_for_dbus_error(LOGIN + ".NoUserForPID", "fixture has no cgroup owner")
            if method == "GetAll" and name in (OWNER, LOGIN) and iface == PROPERTIES:
                return ({USER: self.user, SESSION: self.session, OTHER_SESSION: self.session, SEAT: self.seat}[path],)
            raise AssertionError((name, path, iface, method, signature, args))

        def connection_process(self, sender):
            return self.processes[sender]

        def genuine_gui(self, sender, process):
            return sender != OTHER_APP

    def policy_reply(allowed, challenge, **details):
        return GLib.Variant("((bba{ss}))", ((allowed, challenge, details),))

    def active_signal(active, sender=OWNER):
        message = Gio.DBusMessage.new_signal(SESSION, PROPERTIES, "PropertiesChanged")
        message.set_sender(sender)
        message.set_body(GLib.Variant("(sa{sv}as)", (LOGIN + ".Session", {"Active": GLib.Variant("b", active)}, [])))
        return message


@unittest.skipUnless(sys.platform == "linux", "Linux system-bus and logind credentials")
class SessionAccessTest(unittest.TestCase):
    def setUp(self):
        self.platform = ScopedPlatform()

    def authorize(self):
        self.platform.bus.call_sync.side_effect = [policy_reply(False, True), policy_reply(True, False)]
        return self.platform.open_plan(self.platform.actor(GUI))

    def test_gui_user_scope_needs_new_admin_auth_and_pins_original_connection(self):
        candidate = self.platform.actor(GUI)
        self.assertFalse(candidate.writable)
        self.assertTrue(candidate.can_open_plan)
        self.platform.bus.call_sync.assert_not_called()
        grant = self.authorize()
        self.assertTrue(grant.writable)
        self.assertFalse(grant.can_open_plan)
        self.assertEqual(grant, self.platform.actor(GUI))
        self.assertFalse(self.platform.actor(SECOND_GUI).writable)
        for flags, call in enumerate(self.platform.bus.call_sync.call_args_list):
            authority, _, _, method, params = call.args[:5]
            self.assertEqual((authority, method), (POLKIT, "CheckAuthorization"))
            self.assertEqual(params.unpack(), (("system-bus-name", {"name": GUI}),
                                              "io.github.mknk.BiosUpdate1.open-plan", {}, flags, ""))
        self.platform.processes[GUI] = replace(self.platform.processes[GUI], start="923")
        self.assertFalse(self.platform.actor(GUI).writable)

    def test_direct_gui_keeps_existing_access(self):
        self.platform.direct = True
        actor = self.platform.actor(GUI)
        self.assertTrue(actor.writable)
        self.assertFalse(actor.can_open_plan)
        self.platform.bus.call_sync.assert_not_called()

    def test_service_requires_an_explicit_interactive_request(self):
        service = Service.__new__(Service)
        service.engine = SimpleNamespace(platform=self.platform)
        with self.assertRaises(Conflict):
            service.dispatch(GUI, "OpenPlan", ())
        self.platform.bus.call_sync.assert_not_called()

    def test_unverified_process_owner_and_graphical_session_cannot_open_plan(self):
        actor = self.platform.actor(OTHER_APP)
        self.assertFalse(actor.can_open_plan or actor.writable)
        with self.assertRaises(Conflict):
            self.platform.open_plan(actor)
        for properties, key, value in ((self.platform.user, "UID", 1001),
                                       (self.platform.session, "Active", False),
                                       (self.platform.session, "Remote", True),
                                       (self.platform.user, "Sessions", [("2", SESSION), ("3", OTHER_SESSION)])):
            with self.subTest(key=key), patch.dict(properties, {key: value}), self.assertRaises(Conflict):
                self.platform.actor(GUI)
        for properties, key, value in ((self.platform.user, "Display", ("3", OTHER_SESSION)),
                                       (self.platform.seat, "ActiveSession", ("3", OTHER_SESSION)),
                                       (self.platform.session, "LockedHint", True)):
            with self.subTest(key=key), patch.dict(properties, {key: value}):
                self.assertFalse(self.platform.actor(GUI).can_open_plan)
        self.platform.real_owner = False
        with self.assertRaises(GLib.Error):
            self.platform.actor(GUI)
        self.platform.bus.call_sync.assert_not_called()

    def test_cancelled_or_cached_authentication_does_not_grant_access(self):
        for responses in ([policy_reply(True, False)],
                          [policy_reply(False, True, **{"polkit.retains_authorization_after_challenge": "1"})],
                          [policy_reply(False, True), policy_reply(False, False)]):
            with self.subTest(responses=responses):
                self.platform.bus.call_sync.side_effect = responses
                with self.assertRaises(Conflict):
                    self.platform.open_plan(self.platform.actor(GUI))
                self.assertFalse(self.platform.actor(GUI).writable)
        self.assertTrue(self.authorize().writable)

    def test_session_switch_during_modal_rejects_and_blocks_duplicate_challenge(self):
        def auth(*args):
            if args[4].unpack()[3] == 0:
                return policy_reply(False, True)
            with self.assertRaisesRegex(Conflict, "実行中"):
                self.platform.open_plan(self.platform.actor(SECOND_GUI))
            self.platform.topology_changed(active_signal(False))
            self.platform.topology_changed(active_signal(True))
            return policy_reply(True, False)

        self.platform.bus.call_sync.side_effect = auth
        with self.assertRaisesRegex(Conflict, "切り替わりました"):
            self.platform.open_plan(self.platform.actor(GUI))
        self.assertFalse(self.platform.actor(GUI).writable)

    def test_grant_disappears_on_trusted_topology_change_or_bus_disconnect(self):
        self.authorize()
        self.platform.topology_changed(active_signal(False, sender=OTHER_APP))
        self.assertTrue(self.platform.actor(GUI).writable)
        self.platform.topology_changed(active_signal(False))
        self.platform.topology_changed(active_signal(True))
        self.assertFalse(self.platform.actor(GUI).writable)
        self.authorize()
        message = Gio.DBusMessage.new_signal(DBUS_PATH, DBUS, "NameOwnerChanged")
        message.set_sender(DBUS)
        message.set_body(GLib.Variant("(sss)", (GUI, GUI, "")))
        self.platform.topology_changed(message)
        # Even if an in-flight reader sees the old credentials, the grant is gone.
        self.assertFalse(self.platform.actor(GUI).writable)
