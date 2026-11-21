#!/usr/bin/python3
"""System D-Bus entry point; reads protected observations, brokers validated FDs and journals permissions."""
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import BoundedSemaphore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gi.repository import Gio, GLib
from engine import Engine
from firmware_api import fw
from journal import Conflict, Journal
from platform_linux import Platform


NAME = "io.github.mknk.BiosUpdate1"
OBJECT = "/io/github/mknk/BiosUpdate1"
INTERFACE = "/usr/share/dbus-1/interfaces/io.github.mknk.BiosUpdate1.xml"


class Service:
    def __init__(self, bus, engine, interface):
        self.bus = bus
        self.engine = engine
        self.pool = ThreadPoolExecutor(max_workers=5)
        self.slots = BoundedSemaphore(16)
        self.timer = 0
        self.info = Gio.DBusNodeInfo.new_for_xml(interface)
        self.registration = bus.register_object(OBJECT, self.info.interfaces[0], self.incoming, None, None)
        bus.signal_subscribe("org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
                             "/org/freedesktop/DBus", None, Gio.DBusSignalFlags.NONE, self.owner_changed)
        for signal in ("DeviceAdded", "DeviceRemoved", "DeviceChanged"):
            bus.signal_subscribe("org.freedesktop.fwupd", "org.freedesktop.fwupd", signal, "/", None,
                                 Gio.DBusSignalFlags.NONE, self.observation_changed)
        bus.signal_subscribe("org.freedesktop.UPower", "org.freedesktop.DBus.Properties", "PropertiesChanged",
                             None, None, Gio.DBusSignalFlags.NONE, self.observation_changed)

    def owner_changed(self, conn, sender, path, iface, name, params):
        unique, old, new = params.unpack()
        if unique.startswith(":") and old and not new:
            # Most unique bus names belong to other apps (including inventory helpers).
            if unique in self.engine.drafts or unique in self.engine.candidates:
                self.pool.submit(self.engine.disconnect, unique)
        if unique == "org.freedesktop.fwupd":
            self.observation_changed()

    def observation_changed(self, *unused):
        if not self.timer:
            self.timer = GLib.timeout_add(200, self.notify)

    def notify(self):
        self.timer = 0
        self.bus.emit_signal(None, OBJECT, NAME, "Changed", None)
        return False

    def incoming(self, conn, sender, path, iface, method, parameters, invocation):
        if not self.slots.acquire(blocking=False):
            invocation.return_dbus_error(NAME + ".Busy", "端末サービスが処理中です。少し待って再確認してください。")
            return
        task = self.pool.submit(self.dispatch, sender, method, parameters.unpack())
        task.add_done_callback(lambda done: GLib.idle_add(self.reply, invocation, method, done))

    def dispatch(self, sender, method, args):
        actor = self.engine.platform.actor(sender)
        views = {"Status": self.engine.status, "Check": self.engine.check, "Prepare": self.engine.prepare,
                 "Dismiss": self.engine.dismiss, "Report": self.engine.report, "Replan": self.engine.replan}
        if method in views:
            return GLib.Variant("(s)", (json.dumps(views[method](actor, *args), ensure_ascii=False),)), None
        if method == "Authorize":
            op, owner, device, cabinet = self.engine.authorize(actor, *args)
            with cabinet:
                fds = Gio.UnixFDList.new()
                index = fds.append(cabinet.fileno())
                return GLib.Variant("(sssh)", (op, owner, device, index)), fds
        if method == "Power":
            return GLib.Variant("(sss)", self.engine.power(actor, *args)), None
        if method == "RecheckPower":
            self.engine.recheck_power(actor, *args)
        elif method == "ReplyPower":
            self.engine.db.power_reply(args[0], actor.sender, actor.bus, args[1])
        else:
            raise Conflict("この操作を認識できません。")
        return GLib.Variant("()", ()), None

    def reply(self, invocation, method, result):
        self.slots.release()
        try:
            reply, fds = result.result()
            if fds is not None:
                invocation.return_value_with_unix_fd_list(reply, fds)
            else:
                invocation.return_value(reply)
        except (Conflict, fw.Hold, fw.Error) as exc:
            invocation.return_dbus_error(NAME + ".Hold", str(exc)[:1024])
        except Exception as exc:
            print(f"{method}: {type(exc).__name__}", file=sys.stderr, flush=True)
            invocation.return_dbus_error(NAME + ".Unavailable", "必要な機器・サービス情報を確認できません。状態を再確認してください。")
        if method in ("Authorize", "Report", "Replan", "Dismiss", "Power", "ReplyPower"):
            self.observation_changed()
        return False


def main():
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    state = Path("/var/lib/mknk-bios-update")
    os.umask(0o077)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    engine = Engine(Journal(state / "history.sqlite3"), Platform(bus))
    service = Service(bus, engine, Path(INTERFACE).read_text(encoding="utf-8"))
    loop = GLib.MainLoop()
    Gio.bus_own_name_on_connection(bus, NAME, Gio.BusNameOwnerFlags.NONE, None, lambda *args: loop.quit())
    try:
        loop.run()
    finally:
        service.pool.shutdown(wait=True)


if __name__ == "__main__":
    main()
