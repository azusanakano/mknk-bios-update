"""Fixed Linux integration points for the system service."""
import json
import os
import pwd
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock

from gi.repository import Gio, GLib

import hardware
from catalog import read_trust_policy
from engine import Actor
from firmware_api import fw
from journal import Conflict, METADATA_PENDING


DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
LOGIN = "org.freedesktop.login1"
MANAGER = "/org/freedesktop/login1"
PROPERTIES = DBUS + ".Properties"
POLKIT = "org.freedesktop.PolicyKit1"
POLKIT_AUTHORITY = "/org/freedesktop/PolicyKit1/Authority"
FWUPD = "org.freedesktop.fwupd"
GUI = "/usr/bin/mknk-bios-update"
WORKER = Path(__file__).with_name("worker.py")


class WorkerNotStarted(Conflict):
    """No child was started, so no D-Bus request can be in flight."""


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
        self.session_lock = Lock()
        self.session_owner = None
        self.session_generation = 0
        self.plan_access = {}
        self.opening_plan = {}
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
        return self.login_properties(LOGIN, path, "Session")

    def login_properties(self, owner, path, interface):
        return self.call(owner, path, PROPERTIES, "GetAll", "(s)", (LOGIN + "." + interface,))[0]

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
        try:
            path = self.call(LOGIN, MANAGER, LOGIN + ".Manager", "GetSessionByPID", "(u)", (pid,))[0]
        except GLib.Error as exc:
            if Gio.DBusError.get_remote_error(exc) != LOGIN + ".NoSessionForPID":
                raise
            return self.user_scope_actor(sender, process)
        props = self.session_props(path)
        if not self.session_is_local(props, uid):
            raise Conflict("アクティブなローカル画面で開いてください。")
        return Actor(sender, uid, path, self.bus_id, self.genuine_gui(sender, process),
                     self.desktop(props), f"{pid}:{process.start}")

    def user_scope_actor(self, sender, process):
        uid, pid = process.uid, process.pid
        owner = self.call(DBUS, DBUS_PATH, DBUS, "GetNameOwner", "(s)", (LOGIN,))[0]
        with self.session_lock:
            self.session_owner = owner
            generation = self.session_generation
        # GetUserByPID resolves the owner of the process's real systemd unit.
        # GetUser(uid) would identify an account even for a process outside that unit.
        user = self.call(owner, MANAGER, LOGIN + ".Manager", "GetUserByPID", "(u)", (pid,))[0]
        user_props = self.login_properties(owner, user, "User")
        if user_props.get("UID") != uid:
            raise Conflict("ローカル画面との対応を確認できません。")
        active = []
        for session_id, path in user_props["Sessions"]:
            props = self.login_properties(owner, path, "Session")
            if self.session_is_local(props, uid):
                active.append((session_id, path, props))
        if len(active) != 1:
            raise Conflict("一意のローカル画面を確認できません。")
        session_id, path, props = active[0]
        seat, seat_path = props.get("Seat", ("", "/"))
        timestamp = props.get("TimestampMonotonic")
        display = (session_id, path)
        eligible = bool(seat and timestamp and user_props.get("Display") == display
                        and props.get("LockedHint") is False
                        and self.login_properties(owner, seat_path, "Seat").get("ActiveSession") == display
                        and self.genuine_gui(sender, process))
        if self.connection_process(sender) != process:
            raise Conflict("この画面との接続を確認できません。")
        actor = Actor(sender, uid, path, self.bus_id, False, self.desktop(props), f"{pid}:{process.start}",
                      eligible, (owner, timestamp, generation) if eligible else None)
        with self.session_lock:
            if generation != self.session_generation:
                raise Conflict("ローカル画面が切り替わりました。状態を再確認してください。")
            if eligible and self.plan_access.get(sender) == actor:
                return replace(actor, writable=True, can_open_plan=False)
            self.plan_access.pop(sender, None)
        return actor

    @staticmethod
    def desktop(props):
        desktop = (props.get("Desktop") or "").casefold()
        if "cinnamon" in desktop:
            return "cinnamon"
        if "gnome" in desktop or desktop in ("ubuntu", "ubuntu-xorg", "ubuntu-wayland"):
            return "gnome"
        return ""

    @staticmethod
    def session_is_local(props, uid):
        return (props.get("User", (-1,))[0] == uid and props.get("Active") is True
                and props.get("Remote") is False and props.get("Type") in ("wayland", "x11")
                and props.get("Class") == "user")

    def topology_changed(self, message):
        sender, path = message.get_sender(), message.get_path()
        iface, member = message.get_interface(), message.get_member()
        with self.session_lock:
            if sender == DBUS and path == DBUS_PATH and iface == DBUS and member == "NameOwnerChanged":
                name, old, new = message.get_body().unpack()
                if name.startswith(":") and old and not new:
                    self.plan_access.pop(name, None)
                    for uid, pending in self.opening_plan.items():
                        if pending and pending.sender == name:
                            self.opening_plan[uid] = None
                    return False
                if name != LOGIN:
                    return False
                self.session_owner = new or None
            elif not self.session_owner or sender != self.session_owner:
                return False
            elif iface == PROPERTIES and member == "PropertiesChanged" and path.startswith(MANAGER + "/"):
                interface, changed, invalidated = message.get_body().unpack()
                relevant = {LOGIN + ".Session": {"Active", "LockedHint", "Type"},
                            LOGIN + ".Seat": {"ActiveSession"}, LOGIN + ".User": {"Display"}}
                if not relevant.get(interface, set()).intersection(set(changed).union(invalidated)):
                    return False
            elif path != MANAGER or iface != LOGIN + ".Manager" or member not in ("SessionNew", "SessionRemoved"):
                return False
            self.session_generation += 1
            self.plan_access.clear()
            return True

    def open_plan(self, actor):
        if not actor.can_open_plan or self.actor(actor.sender) != actor:
            raise Conflict("アクティブなローカル画面で「更新計画を開く」を選んでください。")
        with self.session_lock:
            if actor.uid in self.opening_plan:
                raise Conflict("この利用者の管理者認証を実行中です。")
            self.opening_plan[actor.uid] = actor
        failure = "更新計画を開くための管理者認証を完了できませんでした。"
        action, details = "io.github.mknk.BiosUpdate1.open-plan", {}
        if self.portable:
            action = "org.freedesktop.policykit.exec"
            details["polkit.message"] = "この画面で BIOS 更新計画を開くには管理者認証が必要です。"
        retained = {"polkit.retains_authorization_after_challenge", "polkit.temporary_authorization_id"}
        try:
            allowed, challenge, result = self.check_polkit(actor, action, details, 0)
            if allowed or not challenge or retained.intersection(result):
                raise Conflict(failure)
            if self.actor(actor.sender) != actor:
                raise Conflict("ローカル画面が切り替わりました。更新計画を開き直してください。")
            allowed, _, result = self.check_polkit(actor, action, details, 1)
            if not allowed or retained.intersection(result):
                raise Conflict(failure)
            if self.actor(actor.sender) != actor:
                raise Conflict("ローカル画面が切り替わりました。更新計画を開き直してください。")
            with self.session_lock:
                if (self.opening_plan[actor.uid] != actor
                        or actor.session_version[2] != self.session_generation):
                    raise Conflict("ローカル画面が切り替わりました。更新計画を開き直してください。")
                self.plan_access[actor.sender] = actor
            return replace(actor, writable=True, can_open_plan=False)
        except (GLib.Error, OSError) as exc:
            raise Conflict(failure) from exc
        finally:
            with self.session_lock:
                self.opening_plan.pop(actor.uid, None)

    def confirm_owner(self, unique):
        owner = self.call(DBUS, DBUS_PATH, DBUS, "GetNameOwner", "(s)", (FWUPD,))[0]
        if owner != unique or not unique.startswith(":"):
            raise Conflict("fwupd が再起動しました。実機と配布情報を再照合してください。")

    def require_administrator(self, actor):
        action = "io.github.mknk.BiosUpdate1.release-approval"
        details = {}
        if self.portable:
            # Portable mode uses the OS's built-in administrator challenge.
            action = "org.freedesktop.policykit.exec"
            details["polkit.message"] = "元の承認者を確認できない BIOS 更新計画を整理します。"
        try:
            allowed, _, _ = self.check_polkit(actor, action, details, 1)
        except GLib.Error as exc:
            raise Conflict("更新計画の整理に必要な管理者認証を完了できませんでした。") from exc
        if not allowed:
            raise Conflict("更新計画の整理に必要な管理者認証を完了できませんでした。")

    def check_polkit(self, actor, action, details, flags):
        subject = ("system-bus-name", {"name": GLib.Variant("s", actor.sender)})
        params = GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, details, flags, ""))
        return self.bus.call_sync(POLKIT, POLKIT_AUTHORITY, POLKIT + ".Authority", "CheckAuthorization", params,
                                  GLib.VariantType.new("((bba{ss}))"), Gio.DBusCallFlags.NONE, 120000, None).unpack()[0]

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
                self.retire_gui_claim(marker)
            raise

    def release_claim(self, plan):
        boot = hardware._uuid(fw.BOOT_ID)
        if not boot or plan["boot"] != boot:
            raise Conflict("更新の送信許可を記録した起動と一致しません。")
        marker = fw.marker_path()
        if not fw.marker_exists(marker):
            return
        if not self.remove_gui_claim(marker, plan, boot):
            raise Conflict("この更新の送信許可の記録を確認できません。")

    def recover_claim(self, plan):
        boot = hardware._uuid(fw.BOOT_ID)
        return bool(boot and plan["boot"] == boot and self.remove_gui_claim(fw.marker_path(), plan, boot))

    @staticmethod
    def remove_gui_claim(marker, plan, boot):
        if not hardware._owns_marker(marker, plan, boot) or {item.name for item in marker.iterdir()} != {"gui-operation"}:
            return False
        Platform.retire_gui_claim(marker)
        return True

    @staticmethod
    def retire_gui_claim(marker):
        # Remove the published lock name atomically. A crash during cleanup
        # must not leave an empty request in place of a proven unused claim.
        retired = marker.with_name(f".{marker.name}.{uuid.uuid4().hex}")
        marker.rename(retired)
        try:
            (retired / "gui-operation").unlink(missing_ok=True)
            retired.rmdir()
        except OSError:
            # A retired directory in /run has no effect on later requests.
            pass

    def power_allowed(self, actor, action):
        if not actor.desktop:
            raise Conflict("通常のデスクトップ終了経路を確認できません。")
        # CanReboot and CanPowerOff describe the caller. The unprivileged
        # desktop asks those questions after this machine-wide check.
        locks = self.call(LOGIN, MANAGER, LOGIN + ".Manager", "ListInhibitors")[0]
        if any("shutdown" in what.split(":") and how.startswith("block") for what, who, why, how, uid, pid in locks):
            raise Conflict("終了を止めている作業があります。作業を保存してから再確認してください。")
        for sid, uid, name, seat, path in self.call(LOGIN, MANAGER, LOGIN + ".Manager", "ListSessions")[0]:
            if path != actor.session:
                other = self.session_props(path)
                if other.get("Class") in ("user", "user-early") and other.get("State") != "closing":
                    raise Conflict("別のログインセッションで作業中です。保存してログアウトしてください。")

    def start_worker(self, command, **options):
        try:
            return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, **options)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise WorkerNotStarted("配布情報の検証プロセスを起動できませんでした。") from exc

    @staticmethod
    def collect_worker(child, request):
        with child:
            try:
                stdout, _ = child.communicate(request, timeout=240)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise Conflict("配布情報の検証がタイムアウトしました。")
        return subprocess.CompletedProcess(child.args, child.returncode, stdout)

    def execute_worker(self, command, request, **options):
        return self.collect_worker(self.start_worker(command, **options), request)

    def run_worker(self, mode, guid, files=(), *, before_start=None, **args):
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
        if before_start is not None:
            before_start()
        result = self.execute_worker([*python, str(WORKER)], request, pass_fds=tuple(desc),
                                     user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd="/", env=env)
        if result.returncode or len(result.stdout) > 256 * 1024:
            raise Conflict("配布情報の検証プロセスを完了できません。")
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise Conflict("配布情報の検証結果を確認できません。")
        if self.portable:
            try:
                same_profile = args["profile"] == fw.read_settings()
            except (fw.Hold, OSError):
                same_profile = False
            if not same_profile:
                detail = "検証中に機種別の設定が変化しました。配布情報を再確認してください。"
                if mode == "import":
                    # The snapshot can invalidate the result without changing whether the call ended.
                    return dict(terminal=data.get("terminal") is True, ok=False, detail=detail)
                raise Conflict(detail)
        return data

    def worker(self, mode, guid, cabinet=None):
        return self.run_worker(mode, guid, () if cabinet is None else (cabinet,))

    def metadata_clear(self, db):
        while pending := db.setting("metadata-request"):
            if pending["boot"] == fw.BOOT_ID.read_text().strip():
                pid = pending["pid"]
                try:
                    current = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
                except FileNotFoundError:
                    current = None
                if current == pending["start"]:
                    raise Conflict(METADATA_PENDING)
            if db.end_metadata_request(pending):
                return

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
            for stream in (xml, sig):
                stream.seek(0)

            request = dict(id=uuid.uuid4().hex, boot=fw.BOOT_ID.read_text().strip(), pid=pid, start=start,
                           bus=self.bus_id, owner=owner, digest=item["catalog_sha256"])

            def record_import():
                check_caller()
                self.confirm_owner(owner)
                db.begin_metadata_request(request)

            try:
                response = self.run_worker("import", guid, (xml, sig), before_start=record_import, owner=owner,
                                           remote=item["remote_id"], settings_fingerprint=item["settings_fingerprint"],
                                           remote_fingerprint=item["remote_fingerprint"])
            except WorkerNotStarted:
                db.end_metadata_request(request)
                raise
            terminal = response.get("terminal") is True
            if terminal:
                db.end_metadata_request(request)
            if not terminal or response.get("ok") is not True:
                raise Conflict(response.get("detail") or "カタログの取り込み応答が未確定です。")
