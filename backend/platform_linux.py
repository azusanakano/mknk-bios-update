"""Fixed Linux integration points for the system service."""
import json
import os
import pwd
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from gi.repository import Gio, GLib

import hardware
from catalog import read_trust_policy
from engine import Actor
from firmware_api import fw
from journal import Conflict


DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
LOGIN = "org.freedesktop.login1"
MANAGER = "/org/freedesktop/login1"
FWUPD = "org.freedesktop.fwupd"
GUI = "/usr/bin/mknk-bios-update"
WORKER = Path(__file__).with_name("worker.py")


@dataclass(frozen=True)
class BusProcess:
    uid: int
    pid: int
    start: str

    @property
    def proc(self):
        return Path("/proc") / str(self.pid)


class Platform:
    observe = staticmethod(hardware.observe)
    preflight = staticmethod(hardware.preflight)
    check_power_action = staticmethod(hardware.check_power_action)
    recovery_required = staticmethod(hardware.recovery_required)
    cabinet = staticmethod(fw.open_cabinet)

    def __init__(self, bus, *, portable=False):
        self.bus = bus
        self.portable = portable
        self.bus_id = self.call(DBUS, DBUS_PATH, DBUS, "GetId")[0]
        try:
            self.worker_user = pwd.getpwnam("mknk-bios")
        except KeyError:
            if not portable:
                raise
            self.worker_user = pwd.getpwnam("nobody")
        if self.worker_user.pw_uid == 0 or self.worker_user.pw_gid == 0:
            raise Conflict("配布情報を検証する非特権アカウントを確認できません。")

    def call(self, name, path, iface, method, signature=None, args=()):
        params = GLib.Variant(signature, args) if signature else None
        return self.bus.call_sync(name, path, iface, method, params, None, Gio.DBusCallFlags.NONE,
                                  5000, None).unpack()

    def session_props(self, path):
        return self.call(LOGIN, path, DBUS + ".Properties", "GetAll", "(s)", (LOGIN + ".Session",))[0]

    def connection_process(self, sender):
        creds = self.call(DBUS, DBUS_PATH, DBUS, "GetConnectionCredentials", "(s)", (sender,))[0]
        uid, pid = creds["UnixUserID"], creds["ProcessID"]
        stat = (Path("/proc") / str(pid) / "stat").read_bytes()
        return BusProcess(uid, pid, stat.rsplit(b")", 1)[1].split()[19].decode("ascii"))

    def genuine_gui(self, sender, process):
        try:
            return os.path.samefile(process.proc / "exe", GUI)
        except OSError:
            return False

    def actor(self, sender):
        process = self.connection_process(sender)
        uid, pid = process.uid, process.pid
        direct = True
        try:
            path = self.call(LOGIN, MANAGER, LOGIN + ".Manager", "GetSessionByPID", "(u)", (pid,))[0]
        except GLib.Error:
            direct = False
            if f"/user.slice/user-{uid}.slice/user@{uid}.service/" not in (process.proc / "cgroup").read_text():
                raise Conflict("ローカル画面との対応を確認できません。")
            sessions = self.call(LOGIN, MANAGER, LOGIN + ".Manager", "ListSessions")[0]
            active = [row[4] for row in sessions if row[1] == uid and self.session_is_local(self.session_props(row[4]), uid)]
            if len(active) != 1:
                raise Conflict("一意のローカル画面を確認できません。")
            path = active[0]
        props = self.session_props(path)
        if not self.session_is_local(props, uid):
            raise Conflict("アクティブなローカル画面で開いてください。")
        desktop = (props.get("Desktop") or "").casefold()
        if "cinnamon" in desktop:
            desktop = "cinnamon"
        elif "gnome" in desktop or desktop in ("ubuntu", "ubuntu-xorg", "ubuntu-wayland"):
            desktop = "gnome"
        else:
            desktop = ""
        genuine = self.genuine_gui(sender, process)
        return Actor(sender, uid, path, self.bus_id, direct and genuine, desktop, f"{pid}:{process.start}")

    @staticmethod
    def session_is_local(props, uid):
        return (props.get("User", (-1,))[0] == uid and props.get("Active") is True
                and props.get("Remote") is False and props.get("Type") in ("wayland", "x11")
                and props.get("Class") == "user")

    def confirm_owner(self, unique):
        owner = self.call(DBUS, DBUS_PATH, DBUS, "GetNameOwner", "(s)", (FWUPD,))[0]
        if owner != unique or not unique.startswith(":"):
            raise Conflict("fwupd が再起動しました。実機と配布情報を再照合してください。")

    @contextmanager
    def claim(self, plan):
        # Old copies of the terminal client already use this exact per-boot mkdir.
        # Exclusive creation protects both clients even when they reach the last check together.
        marker = fw.marker_path()
        fw.check_marker(marker)
        try:
            marker.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise Conflict("この起動中に別の更新依頼が記録されました。") from exc
        entry = marker / "gui-operation"
        written = False
        try:
            with entry.open("x", encoding="ascii") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(plan["id"])
            written = True
            yield
        except BaseException as exc:
            if not written or isinstance(exc, Conflict):
                entry.unlink(missing_ok=True)
                marker.rmdir()
            raise

    def release_claim(self, plan):
        boot = hardware._uuid(fw.BOOT_ID)
        if not boot or plan["boot"] != boot:
            raise Conflict("更新の送信許可を記録した起動と一致しません。")
        marker = fw.marker_path()
        if not fw.marker_exists(marker):
            return
        if not hardware._owns_marker(marker, plan, boot) or {item.name for item in marker.iterdir()} != {"gui-operation"}:
            raise Conflict("この更新の送信許可の記録を確認できません。")
        (marker / "gui-operation").unlink()
        marker.rmdir()

    def power_allowed(self, actor, action):
        if not actor.desktop:
            raise Conflict("通常のデスクトップ終了経路を確認できません。")
        method = {"reboot": "CanReboot", "shutdown": "CanPowerOff"}[action]
        if self.call(LOGIN, MANAGER, LOGIN + ".Manager", method)[0] != "yes":
            raise Conflict("現在の設定では電源操作を要求できません。")
        locks = self.call(LOGIN, MANAGER, LOGIN + ".Manager", "ListInhibitors")[0]
        if any("shutdown" in what.split(":") and how.startswith("block") for what, who, why, how, uid, pid in locks):
            raise Conflict("終了を止めている作業があります。作業を保存してから再確認してください。")
        for sid, uid, name, seat, path in self.call(LOGIN, MANAGER, LOGIN + ".Manager", "ListSessions")[0]:
            if path != actor.session:
                other = self.session_props(path)
                if other.get("Class") in ("user", "user-early") and other.get("State") != "closing":
                    raise Conflict("別のログインセッションで作業中です。保存してログアウトしてください。")

    def execute_worker(self, command, request, **options):
        return subprocess.run(command, input=request, capture_output=True, timeout=240, check=False, **options)

    def run_worker(self, mode, guid, files=(), **args):
        account = self.worker_user
        desc = [f.fileno() for f in files]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent",
               "MKNK_FWUPD_ONLY_PQ": read_trust_policy()}
        python = ["/usr/bin/python3", "-I"]
        if self.portable:
            # These locations belong to the root-extracted payload. The worker never
            # searches the original AppImage mount or the desktop user's environment.
            stage = WORKER.resolve().parent.parent
            env.update(LD_LIBRARY_PATH=str(stage / "lib"), GI_TYPELIB_PATH=str(stage / "typelibs"))
            python.append("-S")
            args["profile"] = fw.read_settings()
        request = json.dumps(dict(mode=mode, guid=guid, fds=desc, **args)).encode()
        result = self.execute_worker([*python, str(WORKER)], request, pass_fds=tuple(desc),
                                     user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/", env=env)
        if result.returncode or len(result.stdout) > 256 * 1024:
            raise Conflict("配布情報の検証プロセスを完了できません。")
        if self.portable and args["profile"] != fw.read_settings():
            raise Conflict("検証中に機種別の設定が変化しました。配布情報を再確認してください。")
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise Conflict("配布情報の検証結果を確認できません。")
        return data

    def worker(self, mode, guid, cabinet=None):
        return self.run_worker(mode, guid, () if cabinet is None else (cabinet,))

    def metadata_clear(self, db):
        pending = db.setting("metadata-request")
        if not pending:
            return
        if pending["boot"] == fw.BOOT_ID.read_text().strip():
            pid = pending["pid"]
            try:
                current = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
            except FileNotFoundError:
                current = None
            if current == pending["start"]:
                raise Conflict("先のカタログ取り込み結果を確認中です。")
        db.setting("metadata-request", {})

    def refresh(self, guid, db, check_caller):
        self.metadata_clear(db)
        with self.cabinet() as xml, self.cabinet() as sig:
            item = self.run_worker("metadata", guid, (xml, sig))
            if item.get("state") != "metadata":
                raise Conflict(item.get("detail") or "署名済みカタログを確認できません。")
            owner = item["daemon_owner"]
            self.confirm_owner(owner)
            db.catalog_generation(item["signed_timestamp"], item["catalog_sha256"])
            pid = self.call(DBUS, DBUS_PATH, DBUS, "GetConnectionUnixProcessID", "(s)", (owner,))[0]
            start = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
            check_caller()
            self.confirm_owner(owner)
            db.setting("metadata-request", dict(boot=fw.BOOT_ID.read_text().strip(), pid=pid, start=start,
                                               bus=self.bus_id, owner=owner, digest=item["catalog_sha256"]))
            for stream in (xml, sig):
                stream.seek(0)
            response = self.run_worker("import", guid, (xml, sig), owner=owner, remote=item["remote_id"],
                                       settings_fingerprint=item["settings_fingerprint"],
                                       remote_fingerprint=item["remote_fingerprint"])
            if response.get("terminal"):
                db.setting("metadata-request", {})
            if not response.get("ok"):
                raise Conflict(response.get("detail") or "カタログの取り込み応答が未確定です。")
