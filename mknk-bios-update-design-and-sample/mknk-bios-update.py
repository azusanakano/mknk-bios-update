#!/usr/bin/python3
"""ネコシステム社 · LinuxからシステムBIOSの更新を予約する。

  python3 mknk-bios-update.py          機種とLVFS安定版の候補を確認
  python3 mknk-bios-update.py --apply  更新を確認し、対話承認後に予約
  python3 mknk-bios-update.py --status 現在の実機版とfwupdの履歴を表示

対象はUbuntu 24.04 / Linux Mint 22系のUEFI機。fwupd 2.0.20のCLIを基準にする。
通常ユーザーで端末から実行する。保護されたUEFI属性・起動区画の読み取りには必要時のみsudoを使う。
再起動・電源オフ・起動順の独自変更は行わない。ファームウェアの配置はfwupdが行う。
予約対象は標準位置にマウントしたGPTのEFIシステム区画が1つの構成。fwupdの履歴、
標準のディスク配送先、fwupd-efiの予約を確認する。他のOS・ツールで予約済みのPCでは併用を避ける。
終了コード 0=照会完了・取消・受付、1=エラー、2=条件不足、130=中断。
"""

import argparse
import ctypes
import hashlib
from http.client import HTTPException
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen


FWUPDMGR = "/usr/bin/fwupdmgr"
ESRT = Path("/sys/firmware/efi/esrt/entries")
EFIVARS = Path("/sys/firmware/efi/efivars")
DMI = Path("/sys/class/dmi/id")
POWER = Path("/sys/class/power_supply")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
LOCK_DIR = Path("/dev/shm")
MOUNTINFO = Path("/proc/self/mountinfo")
ESP_MOUNTS = (Path("/boot/efi"), Path("/efi"), Path("/boot"))
LSBLK = "/usr/bin/lsblk"
EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
FWUPDATE_GUID = "0abba7dc-e516-4167-bbf5-4d9d1c739416"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
PROTOCOL = "org.uefi.capsule"
REMOTE = "lvfs"
STATES = {1: "予約中", 2: "成功", 3: "失敗", 4: "起動操作待ち", 5: "一時的な失敗"}


class Hold(Exception):
    """判定が成立せず、予約に進めない。"""


class Error(Exception):
    """照会・取得・更新依頼のエラー。"""


def visible(value):
    """機器名などを制御文字を含まない1行として表示する。"""
    return "".join(" " if unicodedata.category(c).startswith("C") else c
                   for c in str(value)).strip()


def strings(item, key):
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
        raise Error(f"fwupdの {key} を解釈できません。")
    return value


def command(args, *, allow_empty=False):
    p = subprocess.run([FWUPDMGR, "--json", "--no-remote-check", "--no-metadata-check",
                        *args], stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, errors="replace")
    if p.returncode == 2 and allow_empty:
        return None
    if p.returncode:
        raise Error(f"fwupdmgr {args[0]} に失敗しました（{p.returncode}）。"
                    f" {visible(p.stderr.strip() or p.stdout.strip())[:600]}")
    return p.stdout


def rows(args, key="Devices", *, allow_empty=False):
    raw = command(args, allow_empty=allow_empty)
    if raw is None:
        return []
    try:
        values = json.loads(raw)[key]
    except (ValueError, KeyError, TypeError) as exc:
        raise Error(f"fwupdmgr {args[0]} のJSONに {key} がありません。") from exc
    if not isinstance(values, list) or not all(isinstance(v, dict) for v in values):
        raise Error(f"fwupdmgr {args[0]} が不明な形式の {key} を返しました。")
    return values


def readonly_sudo(args, purpose):
    if not Path("/usr/bin/sudo").is_file():
        raise Hold(f"{purpose}の権限が必要です。sudoを使用できる端末で実行してください。")
    print(f"{purpose}にsudoを使用します。", flush=True)
    sudo = ["/usr/bin/sudo"] + ([] if sys.stdin.isatty() else ["-n"])
    result = subprocess.run([*sudo, "--", *args], stdout=subprocess.PIPE)
    if result.returncode:
        raise Hold(f"{purpose}が完了しませんでした。")
    return result.stdout


def read_esrt():
    if not ESRT.is_dir():
        raise Hold("UEFIのESRTを取得できません。この方法で更新できるBIOSを特定できません。")
    entries = sorted(p for p in ESRT.iterdir() if re.fullmatch(r"entry[0-9]+", p.name))
    if not entries:
        raise Hold("UEFIから更新対象の資源が公開されていません。")
    paths = [p / field for p in entries for field in ("fw_type", "fw_class")]
    try:
        values = [p.read_text(encoding="ascii").strip() for p in paths]
    except PermissionError:
        values = readonly_sudo(["/usr/bin/cat", "--", *paths], "BIOSの種類とGUIDの読み取り").decode("ascii").splitlines()
    if len(values) != len(paths):
        raise Hold("UEFI資源の一覧を完全に読み取れません。")
    try:
        guids = [str(uuid.UUID(guid)) for kind, guid in zip(values[::2], values[1::2])
                 if int(kind, 0) == 1]
    except ValueError as exc:
        raise Hold("UEFI資源の種類またはGUIDを解釈できません。") from exc
    if len(guids) != 1:
        raise Hold(f"システムBIOSとして登録されたUEFI資源は{len(guids)}件です。対象を確定できません。")
    return guids[0]


def inventory():
    guid = read_esrt()
    devices = rows(["get-devices"])
    matches = [d for d in devices if d.get("Plugin") == "uefi_capsule"
               and PROTOCOL in strings(d, "Protocols") and "internal" in strings(d, "Flags")
               and guid in {s.lower() for s in strings(d, "Guid")}]
    if len(matches) != 1:
        raise Hold(f"UEFIのBIOS資源と一致したfwupd機器は{len(matches)}件です。")
    device = matches[0]
    if not re.fullmatch(r"[0-9a-f]{40}", device.get("DeviceId") or "") or not device.get("Version"):
        raise Hold("BIOSの完全なDevice IDまたは現在版を確認できません。")
    return guid, device, devices


def stable_remote():
    remotes = [r for r in rows(["get-remotes"], "Remotes") if r.get("Id") == REMOTE]
    if len(remotes) != 1 or remotes[0].get("Enabled") is not True or remotes[0].get("Kind") != "download":
        raise Hold("LVFSの安定版配布元 lvfs が有効なダウンロード元になっていません。fwupdmgr get-remotes で確認してください。")
    return remotes[0]


def strong_hash(release):
    checksums = strings(release, "Checksum")
    for size, name in ((64, "sha256"), (128, "sha512")):
        matches = {c.lower() for c in checksums if re.fullmatch(fr"[0-9a-fA-F]{{{size}}}", c)}
        if len(matches) == 1:
            return name, matches.pop()
        if matches:
            raise Hold("同じ方式で異なるCABハッシュが提示されています。")
    raise Hold("候補のCAB全体のSHA-256またはSHA-512を確認できません。")


def candidate(device):
    results = rows(["get-updates", device["DeviceId"]], allow_empty=True)
    if not results:
        return None
    if len(results) != 1 or results[0].get("DeviceId") != device["DeviceId"]:
        raise Hold("更新候補のDevice IDが指定したBIOSと一致しません。")
    releases = results[0].get("Releases", [])
    if not isinstance(releases, list) or not all(isinstance(r, dict) for r in releases):
        raise Error("更新候補の一覧を解釈できません。")
    branch = device.get("Branch") or "default"
    eligible = [r for r in releases if r.get("RemoteId") == REMOTE
                and (r.get("Branch") or "default") == branch
                and not {"blocked-approval", "blocked-version", "is-alternate-branch",
                         "is-downgrade"}.intersection(strings(r, "Flags"))]
    if not eligible:
        return None
    # GetUpgradesは機器のVersionFormatで新しい順に返す。表示文字列を辞書順にしない。
    release = eligible[0]
    if not release.get("Version") or release["Version"] == device["Version"] or not release.get("AppstreamId"):
        raise Hold("目標版または更新コンポーネントを特定できません。")
    key = (release["AppstreamId"], strong_hash(release))
    for other in eligible[1:]:
        if other.get("Version") == release["Version"] and (other.get("AppstreamId"), strong_hash(other)) != key:
            raise Hold("同じ版に異なる配布物があります。更新を一つに絞れません。")
    return release


def check_admin_policy(remote, release):
    # GetUpgradesは現在のfwupdの配布制限を適用する。ローカルCABの送信直前にも確認する。
    hashes = {s.lower() for s in strings(release, "Checksum")}
    if remote.get("ApprovalRequired") is True:
        approved = checksum_list("get-approved-firmware")
        if hashes.isdisjoint(approved):
            raise Hold("管理者の承認一覧にこのCABがありません。")
    # 個別ブロック一覧のCLIは2.0系にあり、2.1.1以降で廃止された。
    help_text = subprocess.run([FWUPDMGR, "--help"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, errors="replace", check=True).stdout
    if re.search(r"(?m)^\s*get-blocked-firmware(?:\s|$)", help_text):
        if hashes.intersection(checksum_list("get-blocked-firmware")):
            raise Hold("このCABは管理者の明示ブロック対象です。")


def checksum_list(action):
    try:
        result = json.loads(command([action]))
        if not isinstance(result, dict) or "Checksums" not in result:
            raise ValueError
        return {s.lower() for s in strings(result, "Checksums")}
    except ValueError as exc:
        raise Error("fwupdの管理者ポリシーを照合できません。") from exc


def check_power():
    # 個体別の最低残量・蓋・画面などの更新条件はfwupdのProblemsと最終検査に従う。
    battery = False
    supplied = False
    for item in POWER.iterdir() if POWER.is_dir() else ():
        if power_field(item, "scope") == "Device":
            continue
        kind = power_field(item, "type")
        if kind == "Battery" and power_field(item, "present") != "0":
            battery = True
        elif kind and kind != "Battery" and power_field(item, "online") == "1":
            supplied = True
    if battery and not supplied:
        raise Hold("内蔵バッテリーを検出しましたが、外部給電を確認できません。ACアダプターを接続してください。")


def power_field(item, name):
    try:
        return (item / name).read_text().strip()
    except FileNotFoundError:
        return ""


def check_esp():
    mounts = {}
    for line in MOUNTINFO.read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        mounts[fields[4]] = (fields[2], fields[3], after.split()[0])
    if mounts.get(str(EFIVARS), (None,) * 3)[1:] != ("/", "efivarfs"):
        raise Hold("EFI変数領域（efivarfs）のマウントを確認できません。")
    p = subprocess.run([LSBLK, "--json", "--list", "--output", "MAJ:MIN,PARTTYPE"],
                       capture_output=True, text=True, check=True)
    parts = {row["maj:min"] for row in json.loads(p.stdout)["blockdevices"]
             if str(row.get("parttype", "")).lower() == ESP_TYPE}
    if len(parts) != 1:
        raise Hold(f"GPTのEFIシステム区画を{len(parts)}件検出しました。更新先を一つに確定できません。")
    number = parts.pop()
    for mount in ESP_MOUNTS:
        if mounts.get(str(mount)) != (number, "/", "vfat"):
            continue
        update_dir = mount / "EFI/UpdateCapsule"
        try:
            occupied = next(update_dir.iterdir(), None) is not None
        except FileNotFoundError:
            occupied = False
        except PermissionError:
            # 既知のマウント位置だけを読み取り、未作成と読取不能を区別する。
            args = ["/usr/bin/find", "-P", str(mount), "-xdev", "-maxdepth", "3",
                    "-ipath", str(update_dir / "*"), "-printf", "x", "-quit"]
            occupied = bool(readonly_sudo(args, "EFI起動区画の既存更新ファイル確認"))
        if occupied:
            raise Hold("EFI/UpdateCapsule に既存の更新ファイルがあります。配送指示が空でも、新規予約は保留します。")
        return
    raise Hold("唯一のEFIシステム区画を /boot/efi、/efi、/boot のいずれにも確認できません。")


def check_nvram_queue():
    # fwupd-efi v1.4のFWUP_UPDATE_INFO v7、先頭4バイトはefivarfsの属性。
    for var in EFIVARS.iterdir():
        if not var.name.lower().endswith("-" + FWUPDATE_GUID):
            continue
        name = var.name[:-(len(FWUPDATE_GUID) + 1)]
        if name in ("FWUPDATE_VERBOSE", "FWUPDATE_DEBUG_LOG"):
            continue
        if not name.startswith("fwupd-"):
            raise Hold("fwupd用EFI名前空間に用途を確認できない既存登録があります。")
        try:
            with var.open("rb") as f:
                header = f.read(56)
        except PermissionError:
            header = readonly_sudo(["/usr/bin/cat", "--", str(var)], "fwupdのEFI予約の読み取り")[:56]
        if (len(header) != 56 or int.from_bytes(header[4:8], "little") != 7
                or int.from_bytes(header[52:56], "little") != 2):
            raise Hold("fwupd-efiに実行待ち、または状態を確定できない更新登録があります。")


def check_ready(device, devices, history):
    flags = set(strings(device, "Flags"))
    problems = strings(device, "Problems")
    if problems or "updatable" not in flags or "emulated" in flags:
        reason = ", ".join(problems) or device.get("UpdateError") or "実機の更新可否を確認できません"
        raise Hold("BIOSを準備できません。 " + visible(reason))
    if "install-all-releases" in flags:
        raise Hold("複数版を一括適用する機種です。このスクリプトでは予約を保留します。")
    attached = {d.get("DeviceId") for d in devices}
    for dev in [*devices, *history]:
        if dev.get("DeviceId") in attached and (dev.get("UpdateState") in (1, 4)
                or {"update-pending", "update-in-progress"}.intersection(strings(dev, "Problems"))):
            raise Hold("fwupdに進行中または起動待ちの更新があります。 " + visible(dev.get("Name", "")))
    check_esp()
    check_nvram_queue()
    try:
        (EFIVARS / f"BootNext-{EFI_GLOBAL}").stat()
    except FileNotFoundError:
        pass
    else:
        raise Hold("別の次回起動先（BootNext）が設定されています。その用途を確認してください。")
    try:
        indications = (EFIVARS / f"OsIndications-{EFI_GLOBAL}").read_bytes()
    except FileNotFoundError:
        pass
    else:
        if len(indications) != 12 or int.from_bytes(indications[4:], "little") & 4:
            raise Hold("既存のディスク経由カプセル配送指示、または判定不能なEFI変数があります。")
    check_power()


def fetch_cab(release, remote, dest):
    algo, expected = strong_hash(release)
    errors = []
    for location in strings(release, "Locations"):
        scheme = urlsplit(location).scheme
        if scheme and scheme != "https":
            continue
        base = remote.get("FirmwareBaseUri")
        if scheme == "https":
            url = location
        elif base:
            url = urljoin(base.rstrip("/") + "/", location.rsplit("/", 1)[-1])
        else:
            url = urljoin(remote.get("MetadataUri", ""), location)
        if urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
            continue
        try:
            req = Request(url, headers={"User-Agent": "mknk-bios-update/1.0"})
            with urlopen(req, timeout=60) as src, dest.open("wb") as dst:
                if urlsplit(src.geturl()).scheme != "https":
                    raise Error("CABの取得先がHTTPS以外に変わりました。")
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        except (URLError, TimeoutError, ConnectionError, HTTPException) as exc:
            errors.append(visible(exc))
            continue
        with dest.open("rb") as stream:
            digest = hashlib.new(algo)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise Hold("ダウンロードしたCABのハッシュがLVFSの配布情報と一致しません。")
        dest.chmod(0o400)
        return
    raise Error("CABをHTTPSで取得できません。 " + (errors[-1] if errors else "配布先を確認してください。"))


def cab_manifest_version(path, app_id):
    """署名・ハッシュ照合後のCABを読み取り、単一リリースの版の原文を取得する。"""
    # libarchive.so.13はUbuntu 24.04のfwupdパッケージの依存ライブラリ。
    lib = ctypes.CDLL("libarchive.so.13")
    ptr = ctypes.c_void_p
    for name, result, args in (
        ("archive_read_new", ptr, []),
        ("archive_read_support_format_cab", ctypes.c_int, [ptr]),
        ("archive_read_open_filename", ctypes.c_int, [ptr, ctypes.c_char_p, ctypes.c_size_t]),
        ("archive_read_next_header", ctypes.c_int, [ptr, ctypes.POINTER(ptr)]),
        ("archive_entry_pathname", ctypes.c_char_p, [ptr]),
        ("archive_read_data", ctypes.c_ssize_t, [ptr, ptr, ctypes.c_size_t]),
        ("archive_read_free", ctypes.c_int, [ptr]),
    ):
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = result, args
    archive = lib.archive_read_new()
    if not archive:
        raise Error("CAB解析用のメモリを確保できません。")
    versions = []
    try:
        if (lib.archive_read_support_format_cab(archive) != 0
                or lib.archive_read_open_filename(archive, os.fsencode(path), 65536) != 0):
            raise Hold("版を確認するためのCABメタデータを開けません。")
        entry = ptr()
        buf = ctypes.create_string_buffer(65536)
        while True:
            code = lib.archive_read_next_header(archive, ctypes.byref(entry))
            if code == 1:  # ARCHIVE_EOF
                break
            if code != 0:
                raise Hold("CAB内のメタデータを列挙できません。")
            name = lib.archive_entry_pathname(entry) or b""
            if not name.lower().endswith(b".metainfo.xml"):
                continue
            data = bytearray()
            while True:
                size = lib.archive_read_data(archive, buf, len(buf))
                if size == 0:
                    break
                if size < 0 or len(data) + size > 2 * 1024 * 1024:
                    raise Hold("CABメタデータを上限内で読み取れません。")
                data.extend(buf.raw[:size])
            try:
                xml = ET.fromstring(data)
            except ET.ParseError as exc:
                raise Hold("CABのAppStreamメタデータを解釈できません。") from exc
            for node in xml.iter():
                node.tag = node.tag.rsplit("}", 1)[-1]
            for component in xml.iter("component"):
                if component.findtext("id") == app_id:
                    versions.extend(r.get("version") for r in component.findall("releases/release"))
    finally:
        lib.archive_read_free(archive)
    if len(versions) != 1 or not versions[0]:
        raise Hold("CAB内の署名対象と単一の目標版を対応付けられません。")
    return versions[0]


def esrt_version(raw, fmt):
    """fwupd 2.0のfu_version_from_uint32に従う。対応外のメーカー形式は保留。"""
    if "." in raw:
        return raw
    if not re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)", raw):
        raise Hold("CAB内のUEFI版を数値として照合できません。")
    val = int(raw, 16 if raw.lower().startswith("0x") else 10)
    if not 0 < val <= 0xffffffff:
        raise Hold("CAB内のUEFI版が32ビット版の範囲外です。")
    a, b, c, d = val.to_bytes(4, "big")
    if fmt in ("number", "plain"):
        return str(val)
    if fmt == "hex":
        return f"0x{val:08x}"
    parts = {"quad": (a, b, c, d), "triplet": (a, b, val & 0xffff),
             "pair": (val >> 16, val & 0xffff), "dell-bios": (b, c, d),
             "dell-bios-msb": (a, b, c)}
    if fmt not in parts:
        raise Hold("この機種のUEFI整数版の表示形式を照合できません。 " + visible(fmt))
    return ".".join(map(str, parts[fmt]))


def verify_cab(path, release, guid, device, devices):
    parts = rows(["get-details", str(path)])
    if len(parts) != 1:
        raise Hold(f"CABに{len(parts)}件の更新コンポーネントがあります。BIOS単体として予約できません。")
    part = parts[0]
    guids = {s.lower() for s in strings(part, "Guid")}
    if guid not in guids or (part.get("DeviceId") and part["DeviceId"] != device["DeviceId"]):
        raise Hold("CABの対象と実機のシステムBIOSが一致しません。")
    group = device.get("CompositeId") or device["DeviceId"]
    for peer in devices:
        if peer.get("DeviceId") == device["DeviceId"] or (peer.get("CompositeId") or peer.get("DeviceId")) != group:
            continue
        ids = {s.lower() for s in strings(peer, "Guid")}
        if not ids or guids.intersection(ids):
            raise Hold("このCABが同じグループの別機器にも適用される可能性があります。")
    details = part.get("Releases", [])
    if not isinstance(details, list) or not all(isinstance(r, dict) for r in details):
        raise Hold("CAB内のリリースを読み取れません。")
    # コンテナ照合用の補助行にはAppstreamIdがない。整数版では本体行にもVersionがない場合がある。
    content = [r for r in details if r.get("AppstreamId")]
    if len(content) != 1 or content[0]["AppstreamId"] != release["AppstreamId"]:
        raise Hold("CAB内のコンポーネント・版が候補と一致しません。")
    if "trusted-payload" not in strings(content[0], "Flags"):
        raise Hold("fwupdでCAB内の更新データの署名を確認できません。")
    version = content[0].get("Version")
    if not version:
        raw = cab_manifest_version(path, release["AppstreamId"])
        version = esrt_version(raw, device.get("VersionFormat"))
    if version != release["Version"]:
        raise Hold("CAB内の目標版がLVFSの更新候補と一致しません。")


def marker_path():
    return LOCK_DIR / ("mknk-bios-update-" + str(uuid.UUID(BOOT_ID.read_text().strip())) + ".request")


def check_marker(path):
    if path.exists():
        raise Hold("このLinux起動中に既に予約を依頼しています。--status で実機版と履歴を確認してください。")


def send_once(path, device, release, cab):
    # 通常のホスト起動で全ローカル利用者が共有するtmpfsに、予約の直前に印を置く。
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    except FileExistsError as exc:
        raise Hold("別の実行が先にこの起動の予約を依頼しました。--status で確認してください。") from exc
    try:
        with os.fdopen(fd, "w") as mark:
            mark.write(f"{device['DeviceId']} {visible(release['Version'])}\n")
        child = subprocess.Popen([FWUPDMGR, "--no-reboot-check", "local-install",
                                  str(cab), device["DeviceId"]])
    except OSError:
        path.unlink()
        raise
    try:
        code = child.wait()
    except KeyboardInterrupt:
        child.wait()
        raise
    if code:
        raise Error(f"fwupdの終了コードは{code}です。依頼後の状態は未確定です。"
                    " --status で確認してください。同じ起動での再送は保留します。")


def describe(device):
    fields = []
    for name in ("sys_vendor", "product_name", "product_sku"):
        try:
            value = visible((DMI / name).read_text(errors="replace"))
        except OSError:
            continue
        if value and value not in fields:
            fields.append(value)
    print("機種     ", " / ".join(fields) or visible(device.get("Name", "不明")))
    print("現在のBIOS", visible(device["Version"]))
    print("Device ID ", device["DeviceId"])


def show_history(device, history):
    matching = [r for r in history if r.get("DeviceId") == device["DeviceId"]]
    if not matching:
        print("このBIOSのfwupd履歴はありません。")
    for r in sorted(matching, key=lambda entry: entry.get("Modified", 0), reverse=True)[:5]:
        targets = [visible(rel["Version"]) for rel in r.get("Releases", [])
                   if isinstance(rel, dict) and rel.get("Version")]
        print("fwupd履歴 ", "・".join(targets) or "目標版不明",
              STATES.get(r.get("UpdateState"), "結果未確定"), visible(r.get("UpdateError", "")))
    if device.get("UpdateState") in (1, 4) or any(r.get("UpdateState") in (1, 4) for r in matching):
        print("fwupdに起動待ちの記録があります。機器とメーカーが指定する起動手順を確認してください。")
    if "needs-shutdown" in strings(device, "Flags"):
        print("この機器は更新の適用に電源オフを必要とします。")


def main():
    parser = argparse.ArgumentParser(description="ネコシステム社 | システムBIOSの確認と更新予約",
                                     epilog="引数なしは --check。実際の適用後は --status で現在版を確認します。")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="LVFS安定版の更新候補を確認（既定）")
    modes.add_argument("--apply", action="store_true", help="内容を確認してBIOS更新を予約")
    modes.add_argument("--status", action="store_true", help="実機版と履歴を表示。配布元への通信なし")
    opt = parser.parse_args()
    if not os.path.isfile(FWUPDMGR):
        raise Error("fwupdmgr が見つかりません。Ubuntu / Mintでは sudo apt install fwupd で導入できます。")
    if opt.apply and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Hold("--apply はfwupdの確認に応答できる対話端末で実行してください。")
    if opt.status:
        _, device, _ = inventory()
        describe(device)
        show_history(device, rows(["get-history"], allow_empty=True))
        if marker_path().exists():
            print("この起動でスクリプトが更新依頼を開始しています。上記の実機版・履歴と併せて確認してください。")
        return
    if not ESRT.is_dir():
        raise Hold("UEFIのESRTを取得できません。この方法で更新できるBIOSを特定できません。")
    remote = stable_remote()
    command(["refresh"], allow_empty=True)  # 2は、直近にカタログを更新済みの場合も返る。
    guid, device, devices = inventory()
    describe(device)
    if opt.apply:
        marker = marker_path()
        check_marker(marker)
        check_ready(device, devices, rows(["get-history"], allow_empty=True))
    release = candidate(device)
    if not release:
        if device.get("UpdateError"):
            print("fwupd    ", visible(device["UpdateError"]))
        message = ("有効なLVFS安定版から、このBIOSの更新候補を取得できませんでした。"
                   " メーカーサイトを含めた最新版かどうかは未確認です。")
        if opt.apply:
            raise Hold(message)
        print(message)
        return
    print("更新候補  ", visible(device["Version"]), "→", visible(release["Version"]), "（lvfs 安定版）")
    if not opt.apply:
        print("予約する場合は --apply を付けて実行してください。")
        return
    with tempfile.TemporaryDirectory(prefix="mknk-bios-") as work:
        cab = Path(work) / "firmware.cab"
        print("配布ファイルを取得し、署名・ハッシュ・対象を照合します。", flush=True)
        fetch_cab(release, remote, cab)
        verify_cab(cab, release, guid, device, devices)
        print("対象     ", visible(release["AppstreamId"]))
        print("CAB      ", *strong_hash(release))
        print("AC電源を維持してください。他のツールで起動待ちの更新を予約済みなら、ここで終了してください。")
        print("予約後は次の通常起動で適用され得ます。再起動のタイミングは利用者が選びます。")
        try:
            consent = input("このBIOS更新を予約しますか [y/N] ").strip().casefold()
        except EOFError:
            consent = ""
        if consent not in ("y", "yes"):
            print("取り消しました。")
            return
        # 承認後も、配布元、対象、現在版、承認した配布物、予約と給電を読み直す。
        active_remote = stable_remote()
        new_guid, current, peers = inventory()
        if new_guid != guid or any(current.get(k) != device.get(k) for k in ("DeviceId", "Version", "Branch", "CompositeId")):
            raise Hold("承認後に機器情報が変化しました。再確認してください。")
        updated = candidate(current)
        if (not updated or any(updated.get(k) != release.get(k) for k in ("Version", "AppstreamId", "RemoteId"))
                or strong_hash(updated) != strong_hash(release)):
            raise Hold("承認後に配布候補が変わりました。再確認してください。")
        verify_cab(cab, updated, guid, current, peers)
        check_ready(current, peers, rows(["get-history"], allow_empty=True))
        check_admin_policy(active_remote, updated)
        send_once(marker, current, updated, cab)
    print("fwupdが更新依頼を受け付けました。BIOSへの適用結果は次の起動後に確認します。")
    try:
        after = rows(["get-devices", current["DeviceId"]])
        if len(after) != 1 or after[0].get("DeviceId") != current["DeviceId"]:
            raise Error("予約後のBIOSを再照合できません。")
        flags = set(strings(after[0], "Flags")) | set(strings(current, "Flags"))
        if "needs-shutdown" in flags:
            print("この機器は電源オフが必要です。通常シャットダウンの後、電源を入れてください。")
        elif "needs-reboot" in flags:
            print("作業を保存し、AC電源を維持した状態で、都合のよい時に通常の再起動を行ってください。")
        else:
            print("適用に必要な起動操作は、fwupdとメーカーの案内を確認してください。")
    except (Error, Hold, OSError) as exc:
        print("予約後の起動手順は未確認です。", visible(exc))
    print("起動後の実機版と履歴は --status で確認できます。")


if __name__ == "__main__":
    try:
        main()
    except Hold as exc:
        print("保留　" + str(exc), file=sys.stderr)
        sys.exit(2)
    except (Error, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("エラー　" + str(exc), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n中断しました。依頼送信中なら --status で状態を確認してください。", file=sys.stderr)
        sys.exit(130)
