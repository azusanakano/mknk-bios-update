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
from engine import Engine
from firmware_api import fw
from journal import Conflict, Journal
from platform_linux import LOGIN, MANAGER, PROPERTIES, Platform


NAME = "io.github.mknk.BiosUpdate1"
OBJECT = "/io/github/mknk/BiosUpdate1"
INTERFACE = "/usr/share/dbus-1/interfaces/io.github.mknk.BiosUpdate1.xml"
STATE = Path("/var/lib/mknk-bios-update")
RECEIPTS = frozenset(("Report", "ReportRejection", "DeclineAuthorization", "ReplyPower"))


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
        # Preserve capacity for terminal reports while reads and workers are busy.
        self.receipt_pool = ThreadPoolExecutor(max_workers=2)
        self.receipt_slots = BoundedSemaphore(4)
        self.timer = 0
        self.closing = False
        self.info = Gio.DBusNodeInfo.new_for_xml(interface)
        self.registration = bus.register_object(OBJECT, self.info.interfaces[0], self.incoming, None, None)
        self.subscriptions = [self.events.signal_subscribe(
            "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
            "/org/freedesktop/DBus", None, Gio.DBusSignalFlags.NONE, self.owner_changed)]
        self.topology_filter = 0
        if isinstance(engine.platform, Platform):
            # Revoke on the bus's incoming message order, before a worker can
            # accept an authorization reply or validate a new write request.
            self.topology_filter = self.events.add_filter(self.session_event, None)
            for interface, signal in ((PROPERTIES, "PropertiesChanged"), (LOGIN + ".Manager", None)):
                self.subscriptions.append(self.events.signal_subscribe(
                    LOGIN, interface, signal, None, None, Gio.DBusSignalFlags.NONE, lambda *unused: None))
        for signal in ("DeviceAdded", "DeviceRemoved", "DeviceChanged"):
            self.subscriptions.append(self.events.signal_subscribe(
                "org.freedesktop.fwupd", "org.freedesktop.fwupd", signal, "/", None,
                Gio.DBusSignalFlags.NONE, self.observation_changed))
        self.subscriptions.append(self.events.signal_subscribe(
            "org.freedesktop.UPower", "org.freedesktop.DBus.Properties", "PropertiesChanged", None, None,
            Gio.DBusSignalFlags.NONE, self.observation_changed))
        for signal in ("SessionNew", "SessionRemoved"):
            self.subscriptions.append(self.events.signal_subscribe(
                LOGIN, LOGIN + ".Manager", signal, MANAGER, None,
                Gio.DBusSignalFlags.NONE, self.observation_changed))
        self.subscriptions.append(self.events.signal_subscribe(
            LOGIN, PROPERTIES, "PropertiesChanged", MANAGER, None,
            Gio.DBusSignalFlags.NONE, self.inhibitors_changed))
        for interface in ("Block", "Partition", "Filesystem"):
            self.subscriptions.append(self.events.signal_subscribe(
                "org.freedesktop.UDisks2", PROPERTIES, "PropertiesChanged", None, "org.freedesktop.UDisks2." + interface,
                Gio.DBusSignalFlags.NONE, self.observation_changed))
        for signal in ("InterfacesAdded", "InterfacesRemoved"):
            self.subscriptions.append(self.events.signal_subscribe(
                "org.freedesktop.UDisks2", "org.freedesktop.DBus.ObjectManager", signal,
                "/org/freedesktop/UDisks2", None, Gio.DBusSignalFlags.NONE, self.observation_changed))

    def close(self):
        self.closing = True
        self.bus.unregister_object(self.registration)
        if self.topology_filter:
            self.events.remove_filter(self.topology_filter)
        for subscription in self.subscriptions:
            self.events.signal_unsubscribe(subscription)
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = 0
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.receipt_pool.shutdown(wait=True)

    def session_event(self, conn, message, incoming, data):
        if (incoming and not self.closing and message.get_message_type() == Gio.DBusMessageType.SIGNAL
                and self.engine.platform.topology_changed(message)):
            GLib.idle_add(self.observation_changed)
        return message

    def owner_changed(self, conn, sender, path, iface, name, params):
        if self.closing:
            return
        unique, old, new = params.unpack()
        if unique.startswith(":") and old and not new:
            # Most unique bus names belong to other apps (including inventory helpers).
            if unique in self.engine.drafts or unique in self.engine.candidates:
                self.pool.submit(self.engine.disconnect, unique)
        if unique in ("org.freedesktop.fwupd", LOGIN, "org.freedesktop.UDisks2", "org.freedesktop.UPower"):
            self.observation_changed()

    def inhibitors_changed(self, conn, sender, path, iface, signal, params):
        interface, changed, invalidated = params.unpack()
        if interface == LOGIN + ".Manager" and {"BlockInhibited", "BlockWeakInhibited"}.intersection(
                set(changed).union(invalidated)):
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
        pool, slots = (self.receipt_pool, self.receipt_slots) if method in RECEIPTS else (self.pool, self.slots)
        if not slots.acquire(blocking=False):
            invocation.return_dbus_error(NAME + ".Busy", "端末サービスが処理中です。少し待って再確認してください。")
            return
        # Peer message headers do not identify a system bus caller. Every method
        # on this connection belongs to the process authenticated at both sockets.
        caller = self.peer_sender if self.peer_sender is not None else sender
        interactive = bool(invocation.get_message().get_flags() & Gio.DBusMessageFlags.ALLOW_INTERACTIVE_AUTHORIZATION)
        task = pool.submit(self.dispatch, caller, method, parameters.unpack(), interactive)
        task.add_done_callback(lambda done: GLib.idle_add(self.reply, invocation, method, done, slots))

    @staticmethod
    def authorization_reply(operation, owner, device, cabinet):
        fds = Gio.UnixFDList.new()
        index = fds.append(cabinet.fileno())
        return GLib.Variant("(sssh)", (operation, owner, device, index)), fds

    def receipt_view(self, sender, args):
        platform = self.engine.platform
        # Receipt ownership is independent of the caller's current right to see the machine.
        self.engine.record_receipt(sender, platform.bus_id, *args)
        try:
            actor = platform.actor(sender)
            view = self.engine.status(actor)
            if platform.actor(sender) == actor:
                return view
        except (Conflict, GLib.Error, OSError):
            pass
        return {"recorded": True}

    def dispatch(self, sender, method, args, interactive=False):
        platform = self.engine.platform
        if method in ("Report", "ReportRejection"):
            return GLib.Variant("(s)", (json.dumps(self.receipt_view(sender, args), ensure_ascii=False),)), None
        if method == "DeclineAuthorization":
            self.engine.decline_authorization(sender, args[0])
            return GLib.Variant("()", ()), None
        if method == "ReplyPower":
            self.engine.db.power_reply(args[0], sender, platform.bus_id, args[1])
            return GLib.Variant("()", ()), None
        actor = platform.actor(sender)
        if method == "OpenPlan":
            if not interactive:
                raise Conflict("更新計画を開くには画面で管理者認証を開始してください。")
            actor = platform.open_plan(actor)
            self.engine.required(actor)
            method = "Status"
        if self.peer_sender is not None and method != "Status" and not actor.writable:
            raise Conflict("操作するには、アクティブなローカル画面から開いてください。")
        views = {"Status": self.engine.status, "Check": self.engine.check, "Prepare": self.engine.prepare,
                 "Dismiss": self.engine.dismiss, "Replan": self.engine.replan, "TakeOver": self.engine.take_over}
        if method in views:
            return GLib.Variant("(s)", (json.dumps(views[method](actor, *args), ensure_ascii=False),)), None
        if method == "Authorize":
            return self.engine.authorize(actor, *args, prepare_reply=self.authorization_reply)
        if method == "Power":
            return GLib.Variant("(sss)", self.engine.power(actor, *args)), None
        if method == "CheckPower":
            return GLib.Variant("(s)", (self.engine.check_power(actor, *args),)), None
        if method == "RecheckPower":
            self.engine.recheck_power(actor, *args)
        else:
            raise Conflict("この操作を認識できません。")
        return GLib.Variant("()", ()), None

    def reply(self, invocation, method, result, slots):
        slots.release()
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
