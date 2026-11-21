#!/usr/bin/python3
"""One explicitly authorized AppImage GUI, one private Linux D-Bus connection."""
import fcntl
import hashlib
import os
import re
import secrets
import signal
import subprocess
import sys
from pathlib import Path
from threading import Lock


BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))
from gi.repository import Gio, GLib
from engine import Engine
from journal import Conflict, Journal
from platform_linux import DBUS, DBUS_PATH, Platform
from service import NAME, Service, machine_state


GUI_ERROR = "起動した AppImage と、この画面の利用者・プロセスが一致しません。画面を開き直してください。"
INSTALLED = "インストール済みの BIOS 更新サービスがあります。アプリ一覧の「BIOS 更新」を開いてください。"
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL


def pkexec_uid(value):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value or "") or int(value) >= 2**32 - 1:
        raise Conflict("デスクトップから管理者認証を受けた利用者を確認できません。")
    return int(value)


def open_verified_gui(path, expected):
    # AppRun executes an immutable memfd. This works even when the user's FUSE mount
    # is invisible to root. Keep the verified inode open across every later check.
    image = path.open("rb", buffering=0)
    try:
        if fcntl.fcntl(image.fileno(), fcntl.F_GET_SEALS) & SEALS != SEALS:
            raise Conflict(GUI_ERROR)
        if os.fstat(image.fileno()).st_size > 64 * 1024 * 1024:
            raise Conflict(GUI_ERROR)
        if hashlib.file_digest(image, "sha256").hexdigest() != expected:
            raise Conflict(GUI_ERROR)
        return image
    except OSError as exc:
        image.close()
        raise Conflict(GUI_ERROR) from exc
    except BaseException:
        image.close()
        raise


class PortablePlatform(Platform):
    def __init__(self, bus, sender, uid, expected):
        if not Gio.dbus_is_unique_name(sender):
            raise Conflict(GUI_ERROR)
        super().__init__(bus, portable=True)
        self.sender = sender
        self.process = self.connection_process(sender)
        if self.process.uid != uid:
            raise Conflict(GUI_ERROR)
        self.image = open_verified_gui(self.process.proc / "exe", expected)
        self.peer = None
        self.workers = set()
        self.worker_lock = Lock()
        self.revoked = False

    def credentials_match(self, credentials):
        return (credentials is not None and credentials.get_unix_user() == self.process.uid
                and credentials.get_unix_pid() == self.process.pid)

    def verify_process(self, sender, process):
        if (sender != self.sender or process != self.process
                or process.proc.stat().st_uid != process.uid
                or not os.path.samefile(process.proc / "exe", self.image.fileno())):
            raise Conflict(GUI_ERROR)

    def genuine_gui(self, sender, process):
        # Platform.actor has just resolved the name, UID, PID, start time and
        # local session again. Revoking the peer also invalidates in-flight plans.
        peer = self.peer
        if self.revoked or peer is None or peer.is_closed():
            raise Conflict(GUI_ERROR)
        self.verify_process(sender, process)
        return True

    def check_installed_service(self):
        if (self.call(DBUS, DBUS_PATH, DBUS, "NameHasOwner", "(s)", (NAME,))[0]
                or NAME in self.call(DBUS, DBUS_PATH, DBUS, "ListActivatableNames")[0]):
            raise Conflict(INSTALLED)

    def execute_worker(self, command, request, **options):
        # A download can outlive the window by minutes. Stop disposable workers on
        # disconnect, then let the engine finish its journal transaction and close FDs.
        with self.worker_lock:
            if self.revoked:
                raise Conflict(GUI_ERROR)
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, **options)
            self.workers.add(child)
        try:
            with child:
                try:
                    stdout, _ = child.communicate(request, timeout=240)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
                    raise Conflict("配布情報の検証がタイムアウトしました。")
            return subprocess.CompletedProcess(command, child.returncode, stdout)
        finally:
            with self.worker_lock:
                self.workers.discard(child)

    def revoke(self):
        self.peer = None
        with self.worker_lock:
            self.revoked = True
            for child in self.workers:
                child.kill()


class PeerServer:
    def __init__(self, engine, interface):
        self.engine = engine
        self.platform = engine.platform
        self.interface = interface
        self.loop = GLib.MainLoop()
        self.service = None
        self.stopping = False
        self.deadline = 0
        observer = Gio.DBusAuthObserver.new()
        observer.connect("allow-mechanism", lambda _, mechanism: mechanism == "EXTERNAL")
        observer.connect("authorize-authenticated-peer", self.authenticate)
        address = "unix:abstract=mknk-bios-" + secrets.token_hex(16)
        self.server = Gio.DBusServer.new_sync(address, Gio.DBusServerFlags.NONE,
                                              Gio.dbus_generate_guid(), observer, None)
        self.server.connect("new-connection", self.accept)

    def authenticate(self, observer, stream, credentials):
        try:
            return (self.platform.credentials_match(credentials)
                    and self.platform.credentials_match(stream.get_socket().get_credentials()))
        except (GLib.Error, OSError):
            return False

    def accept(self, server, connection):
        if self.stopping or self.service is not None:
            return False
        try:
            if not self.platform.credentials_match(connection.get_peer_credentials()):
                return False
            self.platform.verify_process(self.platform.sender, self.platform.connection_process(self.platform.sender))
            if not connection.get_capabilities() & Gio.DBusCapabilityFlags.UNIX_FD_PASSING:
                raise Conflict("この画面との接続では検証済みファイルを受け渡せません。")
            self.service = Service(connection, self.engine, self.interface,
                                   system_bus=self.platform.bus, peer_sender=self.platform.sender)
        except (Conflict, GLib.Error, OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr, flush=True)
            self.stop()
            return False
        self.platform.peer = connection
        connection.connect("closed", self.stop)
        server.stop()
        if self.deadline:
            GLib.source_remove(self.deadline)
            self.deadline = 0
        return True

    def stop(self, *unused):
        self.stopping = True
        self.platform.revoke()
        self.loop.quit()

    def timed_out(self):
        self.deadline = 0
        self.stop()
        return False

    def run(self, ready, timeout_ms=30000):
        bus = self.platform.bus
        flags = Gio.BusNameWatcherFlags.NONE
        gui_watch = Gio.bus_watch_name_on_connection(bus, self.platform.sender, flags, None, self.stop)
        installed_watch = Gio.bus_watch_name_on_connection(bus, NAME, flags, self.stop, None)
        bus_closed = bus.connect("closed", self.stop)
        try:
            self.platform.check_installed_service()
            self.deadline = GLib.timeout_add(timeout_ms, self.timed_out)
            self.server.start()
            ready(self.server.get_client_address())
            if not self.stopping:
                self.loop.run()
        finally:
            self.stop()
            self.server.stop()
            if self.deadline:
                GLib.source_remove(self.deadline)
                self.deadline = 0
            Gio.bus_unwatch_name(gui_watch)
            Gio.bus_unwatch_name(installed_watch)
            bus.disconnect(bus_closed)
            if self.service is not None:
                connection = self.service.bus
                try:
                    if not connection.is_closed():
                        connection.close_sync(None)
                finally:
                    self.service.close()
                    self.engine.disconnect(self.platform.sender)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise Conflict("AppImage の画面から管理者認証を開始してください。")
    uid = pkexec_uid(os.environ.get("PKEXEC_UID"))
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    bus.set_exit_on_close(False)
    expected = (BACKEND / "gui.sha256").read_text(encoding="ascii").strip()
    platform = PortablePlatform(bus, sys.argv[1], uid, expected)
    try:
        platform.check_installed_service()
        with machine_state() as state:
            engine = Engine(Journal(state / "history.sqlite3"), platform)
            interface = (BACKEND / (NAME + ".xml")).read_text(encoding="utf-8")
            server = PeerServer(engine, interface)
            # pkexec can exit with the GUI and its bootstrap forwards SIGTERM.
            # Run the same cleanup as a closed socket before staging is removed.
            def terminate():
                server.stop()
                return GLib.SOURCE_CONTINUE
            term = GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, terminate)
            try:
                server.run(lambda address: print(address, flush=True))
            finally:
                GLib.source_remove(term)
    finally:
        platform.image.close()


if __name__ == "__main__":
    try:
        main()
    except Conflict as exc:
        sys.exit(str(exc))
    except (GLib.Error, KeyError, OSError, ValueError) as exc:
        print(f"端末の更新サービスを開始できません。({type(exc).__name__})", file=sys.stderr)
        sys.exit(1)
