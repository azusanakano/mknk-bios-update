"""One fixed, unprivileged validation job. Firmware installation is handled by the GUI."""
import json
import os
import re
import sys
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog
from firmware_api import fw


def import_metadata(request, files):
    import fcntl
    from gi.repository import Gio, GLib
    owner, remote = request["owner"], request["remote"]
    if not Gio.dbus_is_unique_name(owner) or not re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        raise ValueError("invalid destination")
    settings = fw.read_settings()
    session = catalog.Session()
    live = session.remote(settings)
    if (catalog.fingerprint(settings) != request["settings_fingerprint"] or session.current_owner() != owner
            or live["Id"] != remote or catalog.remote_fingerprint(live) != request["remote_fingerprint"]):
        return dict(terminal=True, ok=False, detail="取り込み前に配布設定が変わりました。")
    fds = Gio.UnixFDList.new()
    for stream in files:
        required = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
        if fcntl.fcntl(stream.fileno(), fcntl.F_GET_SEALS) & required != required:
            raise ValueError("unsealed metadata")
        stream.seek(0)
        fds.append(stream.fileno())
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    try:
        bus.call_with_unix_fd_list_sync(owner, "/", "org.freedesktop.fwupd", "UpdateMetadata",
                                        GLib.Variant("(shh)", (remote, 0, 1)), None, Gio.DBusCallFlags.NO_AUTO_START,
                                        120000, fds, None)
        return dict(terminal=True, ok=True)
    except GLib.Error as exc:
        error = Gio.DBusError.get_remote_error(exc) or ""
        return dict(terminal=error.startswith("org.freedesktop.fwupd.") or
                    error == "org.freedesktop.DBus.Error.ServiceUnknown",
                    ok=error.endswith(".NothingToDo"), detail="fwupd が配布情報の取り込みを完了できませんでした。")


def main():
    if os.geteuid() == 0:
        raise RuntimeError("catalog worker requires an unprivileged account")
    request = json.load(sys.stdin)
    if "profile" in request:
        # The portable parent read and validated this snapshot as root. It
        # checks the canonical file again before accepting the worker's result.
        profile = request["profile"]
        if not isinstance(profile, dict):
            raise ValueError("invalid device profile")
        fw.read_settings = lambda: profile
    mode = request["mode"]
    with ExitStack() as stack:
        files = [stack.enter_context(os.fdopen(f, "r+b")) for f in request["fds"]]
        if mode == "metadata":
            result = catalog.fetch_metadata(request["guid"], *files)
        elif mode == "import":
            result = import_metadata(request, files)
        elif mode in ("check", "prepare", "revalidate"):
            result = catalog.query(mode, request["guid"], *files)
        else:
            raise ValueError("unknown operation")
        json.dump(result, sys.stdout, ensure_ascii=True)


if __name__ == "__main__":
    main()
