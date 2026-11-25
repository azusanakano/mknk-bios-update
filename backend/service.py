#!/usr/bin/python3
"""D-Bus API for protected observations, validated FDs and journaled permissions."""
import fcntl
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import BoundedSemaphore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gi.repository import Gio, GLib
from engine import Actor, Engine
from firmware_api import fw
from journal import Conflict, Journal
from platform_linux import Platform


NAME = "io.github.mknk.BiosUpdate1"
OBJECT = "/io/github/mknk/BiosUpdate1"
INTERFACE = "/usr/share/dbus-1/interfaces/io.github.mknk.BiosUpdate1.xml"
STATE = Path("/var/lib/mknk-bios-update")


@contextmanager
def machine_state():
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    # Lock the directory itself. Replacing or unlinking a lock file could
    # otherwise let two transports operate on the same journal independently.
    directory = os.open(STATE, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(directory)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise Conflict("端末の履歴を安全に保存するためのディレクトリを確認できません。")
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Conflict("別の BIOS 更新画面が端末の履歴を使用しています。先にその画面を閉じてください。") from exc
        yield STATE
    finally:
        os.close(directory)


class Service:
    def __init__(self, bus, engine, interface, *, system_bus=None, peer_sender=None):
        self.bus = bus
        self.events = bus if system_bus is None else system_bus
        self.peer_sender = peer_sender
        self.engine = engine
        self.pool = ThreadPoolExecutor(max_workers=5)
        self.slots = BoundedSemaphore(16)
        self.timer = 0
        self.closing = False
        self.info = Gio.DBusNodeInfo.new_for_xml(interface)
        self.registration = bus.register_object(OBJECT, self.info.interfaces[0], self.incoming, None, None)
        self.subscriptions = [self.events.signal_subscribe(
            "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
            "/org/freedesktop/DBus", None, Gio.DBusSignalFlags.NONE, self.owner_changed)]
        for signal in ("DeviceAdded", "DeviceRemoved", "DeviceChanged"):
            self.subscriptions.append(self.events.signal_subscribe(
                "org.freedesktop.fwupd", "org.freedesktop.fwupd", signal, "/", None,
                Gio.DBusSignalFlags.NONE, self.observation_changed))
        self.subscriptions.append(self.events.signal_subscribe(
            "org.freedesktop.UPower", "org.freedesktop.DBus.Properties", "PropertiesChanged", None, None,
            Gio.DBusSignalFlags.NONE, self.observation_changed))

    def close(self):
        self.closing = True
        self.bus.unregister_object(self.registration)
        for subscription in self.subscriptions:
            self.events.signal_unsubscribe(subscription)
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        self.pool.shutdown(wait=True, cancel_futures=True)

    def owner_changed(self, conn, sender, path, iface, name, params):
        if self.closing:
            return
        unique, old, new = params.unpack()
        if unique.startswith(":") and old and not new:
            # Most unique bus names belong to other apps (including inventory helpers).
            if unique in self.engine.drafts or unique in self.engine.candidates:
                self.pool.submit(self.engine.disconnect, unique)
        if unique == "org.freedesktop.fwupd":
            self.observation_changed()

    def observation_changed(self, *unused):
        if not self.closing and not self.timer:
            self.timer = GLib.timeout_add(200, self.notify)

    def notify(self):
        self.timer = 0
        if not self.bus.is_closed():
            self.bus.emit_signal(None, OBJECT, NAME, "Changed", None)
        return False

    def incoming(self, conn, sender, path, iface, method, parameters, invocation):
        if not self.slots.acquire(blocking=False):
            invocation.return_dbus_error(NAME + ".Busy", "端末サービスが処理中です。少し待って再確認してください。")
            return
        # Peer message headers do not identify a system bus caller. Every method
        # on this connection belongs to the process authenticated at both sockets.
        caller = self.peer_sender if self.peer_sender is not None else sender
        task = self.pool.submit(self.dispatch, caller, method, parameters.unpack())
        task.add_done_callback(lambda done: GLib.idle_add(self.reply, invocation, method, done))

    def dispatch(self, sender, method, args):
        platform = self.engine.platform
        receipt = method in ("Report", "ReportRejection")
        if method == "DeclineAuthorization":
            self.engine.decline_authorization(sender, args[0])
            return GLib.Variant("()", ()), None
        if method == "ReplyPower":
            self.engine.db.power_reply(args[0], sender, platform.bus_id, args[1])
            return GLib.Variant("()", ()), None
        try:
            actor = platform.actor(sender)
        except (Conflict, GLib.Error, OSError):
            if not receipt:
                raise
            # The journal binds the receipt to the original unique connection and bus.
            # A session switch removes write access to the view but does not lose its receipt.
            actor = Actor(sender, -1, "", platform.bus_id, False, "", "")
        if self.peer_sender is not None and method != "Status" and not receipt and not actor.writable:
            raise Conflict("操作するには、アクティブなローカル画面から開いてください。")
        views = {"Status": self.engine.status, "Check": self.engine.check, "Prepare": self.engine.prepare,
                 "Dismiss": self.engine.dismiss, "Report": self.engine.report, "Replan": self.engine.replan,
                 "ReportRejection": self.engine.report_rejection, "TakeOver": self.engine.take_over}
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
        else:
            raise Conflict("この操作を認識できません。")
        return GLib.Variant("()", ()), None

    def reply(self, invocation, method, result):
        self.slots.release()
        if self.closing or self.bus.is_closed():
            return False
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
        if method in ("Authorize", "DeclineAuthorization", "Report", "ReportRejection",
                      "Replan", "Dismiss", "TakeOver", "Power", "ReplyPower"):
            self.observation_changed()
        return False


def main():
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    with machine_state() as state:
        engine = Engine(Journal(state / "history.sqlite3"), Platform(bus))
        service = Service(bus, engine, Path(INTERFACE).read_text(encoding="utf-8"))
        loop = GLib.MainLoop()
        Gio.bus_own_name_on_connection(bus, NAME, Gio.BusNameOwnerFlags.NONE, None, lambda *args: loop.quit())
        try:
            loop.run()
        finally:
            service.close()


if __name__ == "__main__":
    main()
