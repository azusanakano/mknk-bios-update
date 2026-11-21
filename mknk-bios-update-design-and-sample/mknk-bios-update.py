#!/usr/bin/python3
"""ネコシステム社 · LinuxからシステムBIOSの更新を予約する。

  python3 mknk-bios-update.py          機種とLVFS安定版の候補を確認
  python3 mknk-bios-update.py --apply  更新を確認し、対話承認後に予約
  python3 mknk-bios-update.py --status 現在の実機版、EFIの予約、fwupdの履歴を表示

対象はUbuntu 24.04 / Linux Mint 22系のUEFI機。fwupd 2.0.20のCLIを基準にする。
通常ユーザーで端末から実行する。保護されたUEFI属性・起動区画の読み取りと、同じ起動での
再送を防ぐ端末共通の依頼記録にはsudoを使う。
再起動・電源オフ・起動順の独自変更は行わない。ファームウェアの配置はfwupdが行う。
予約対象はfwupdの配送区画候補が標準位置のGPT ESPに一意に一致する構成。fwupdの履歴、
標準とDell固有のディスク配置先、fwupd-efiの予約を確認する。他のOS・ツールで予約済みのPCでは併用を避ける。
終了コード 0=照会完了・取消・受付、1=エラー、2=条件不足、130=中断。
"""

import argparse
import ctypes
from functools import cache, reduce
import gzip
import hashlib
from http.client import HTTPException
import io
import json
import lzma
import operator
import os
import re
import stat
import struct
import subprocess
import sys
from typing import NamedTuple
import unicodedata
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


FWUPDMGR = "/usr/bin/fwupdmgr"
ESRT = Path("/sys/firmware/efi/esrt/entries")
EFIVARS = Path("/sys/firmware/efi/efivars")
EFI_PLATFORM_SIZE = Path("/sys/firmware/efi/fw_platform_size")
EFI_APP_DIR = Path("/usr/libexec/fwupd/efi")
DMI = Path("/sys/class/dmi/id")
SUPPORT_PROFILE = Path("/etc/mknk-bios-update.json")
MODEL_FIELDS = ("sys_vendor", "product_name", "product_sku", "board_name", "board_version")
GUID_TEXT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
POWER = Path("/sys/class/power_supply")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
LOCK_DIR = Path("/run")
LEGACY_LOCK_DIR = Path("/dev/shm")
MOUNTINFO = Path("/proc/self/mountinfo")
ESP_MOUNTS = (Path("/boot/efi"), Path("/efi"), Path("/boot"))
LSBLK = "/usr/bin/lsblk"
EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"
FWUPDATE_GUID = "0abba7dc-e516-4167-bbf5-4d9d1c739416"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
BDP_TYPE = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
UDISKS = "org.freedesktop.UDisks2"
FMP_CAPSULE = uuid.UUID("6dcbd5ed-e82d-4c44-bda1-7194199ad92a").bytes_le
PROTOCOL = "org.uefi.capsule"
FWUPD_ID = "org.freedesktop.fwupd"
CLIENT_FEATURES = ("requests", "requests-non-generic", "detach-action", "update-action",
                   "allow-authentication", "fde-warning", "show-problems")
UNSUPPORTED_CLIENT_FEATURES = {"switch-branch", "community-text", "can-report", "none"}
VERSION_COMPARISONS = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt,
                       "gt": operator.gt, "le": operator.le, "ge": operator.ge}
REMOTE = "lvfs"
LVFS_METADATA_URIS = frozenset({"https://cdn.fwupd.org/downloads/firmware.xml.xz",
                               "https://cdn.fwupd.org/downloads/firmware.xml.zst"})
LVFS_CAB_BASE_URIS = ("https://cdn.fwupd.org/downloads/", "https://fwupd.org/downloads/")
REMOTE_URI_FIELDS = ("MetadataUri", "MetadataUriSig", "FirmwareBaseUri")
METADATA_LIMIT = 32 * 1024 * 1024
METADATA_SIG_LIMIT = 1024 * 1024
METADATA_XML_LIMIT = 256 * 1024 * 1024
CAB_DOWNLOAD_LIMIT = 256 * 1024 * 1024
STATES = {1: "予約中", 2: "成功", 3: "失敗", 4: "起動操作待ち", 5: "一時的な失敗"}
STANDARD_CAPSULE_DIR = "EFI/UpdateCapsule"
DELL_RECOVERY_FILE = "EFI/dell/bios/recovery/BIOS_TRS.rcv"
DISK_DELIVERY_PATHS = ((STANDARD_CAPSULE_DIR, True), (DELL_RECOVERY_FILE, False))


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


def sudo_command(args, purpose):
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
        values = sudo_command(["/usr/bin/cat", "--", *paths], "BIOSの種類とGUIDの読み取り").decode("ascii").splitlines()
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


def inventory(guid=None, *, devices=None):
    if guid is None:
        guid = read_esrt()
    if devices is None:
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


def read_settings():
    try:
        fd = os.open(SUPPORT_PROFILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Hold("対応情報はroot所有で、一般ユーザーが書き込めない通常ファイルにしてください。")
            raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise Hold("対応情報のファイルが大きすぎます。")
            profile = json.loads(raw)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise Hold(f"検証済みの機種別対応情報を {SUPPORT_PROFILE} から読めません。") from exc
    if not isinstance(profile, dict):
        raise Hold(f"{SUPPORT_PROFILE} はJSONオブジェクトで指定してください。")
    return profile


def support_profile(settings, guid, device):
    if "dmi" not in settings:
        raise Hold(f"更新を予約するには {SUPPORT_PROFILE} に検証済みの機種別対応情報が必要です。")
    model = {}
    for field in MODEL_FIELDS:
        try:
            model[field] = (DMI / field).read_text().strip()
        except FileNotFoundError:
            model[field] = ""
    if not model["sys_vendor"] or not model["product_name"]:
        raise Hold("カプセルの検証に必要な機種情報を確認できません。")
    versions = settings.get("bios_versions")
    if (settings.get("dmi") != model or settings.get("esrt_guid") != guid
            or not isinstance(versions, list) or device["Version"] not in versions):
        raise Hold("実機の機種、ESRT GUID、現在のBIOS版が検証済みの対応情報と一致しません。")
    return settings


def https_origin_path(url):
    if not isinstance(url, str) or not url.isascii() or re.search(r"[\x00-\x20\x7f\\?#]", url):
        raise Hold("配布先には認証情報やクエリを含まないHTTPSのURIが必要です。")
    try:
        parsed = urlsplit(url)
        port = 443 if parsed.port is None else parsed.port
        path = unquote(parsed.path, errors="strict")
    except ValueError as exc:
        raise Hold("配布先のURIを解釈できません。") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or port == 0
            or not path.startswith("/") or "//" in path or {".", ".."}.intersection(path.split("/"))
            or re.search(r"%(?![0-9a-f]{2})|%2f", parsed.path, re.IGNORECASE)
            or re.search(r"[\x00-\x1f\x7f%\\?#;]", path)):
        raise Hold("配布先のHTTPSホスト・ポート・パスを確定できません。")
    return parsed.hostname, port, path


def stable_remote(settings, *, remotes=None, remote_id=REMOTE, allow_credentials=False):
    if remotes is None:
        remotes = rows(["get-remotes"], "Remotes")
    remotes = [r for r in remotes if r.get("Id") == remote_id]
    if len(remotes) != 1 or remotes[0].get("Enabled") is not True or remotes[0].get("Kind") != "download":
        raise Hold("LVFSの安定版配布元 lvfs が有効なダウンロード元になっていません。fwupdmgr get-remotes で確認してください。")
    remote = remotes[0]
    mirrors = settings.get("stable_metadata_uris", [])
    if not isinstance(mirrors, list) or not all(isinstance(uri, str) for uri in mirrors):
        raise Hold("安定版ミラーのメタデータURIを確認できません。")
    uri = remote.get("MetadataUri")
    host, _, _ = https_origin_path(uri)
    public = remote_id == REMOTE and uri in LVFS_METADATA_URIS
    if not public and (uri not in mirrors or host in ("cdn.fwupd.org", "fwupd.org")):
        raise Hold("lvfs のメタデータURIが公開安定版または検証済み安定版ミラーと一致しません。")
    if (remote.get("Username") or remote.get("Password")) and not allow_credentials:
        raise Hold("このサンプルでは認証情報を含まないHTTPSの安定版配布元を指定してください。")
    return remote


def compare_remote(previous, current):
    if any(previous.get(key) != current.get(key) for key in REMOTE_URI_FIELDS):
        raise Hold("照会後にLVFSの取得先が変化しました。配布元を再確認してください。")


def strong_hashes(checksums):
    hashes = {}
    for size, name in ((64, "sha256"), (128, "sha512")):
        matches = {c.lower() for c in checksums if re.fullmatch(fr"[0-9a-fA-F]{{{size}}}", c)}
        if len(matches) > 1:
            raise Hold("同じ方式で異なるCABハッシュが提示されています。")
        if matches:
            hashes[name] = matches.pop()
    return hashes


def release_hashes(release):
    hashes = strong_hashes(strings(release, "Checksum"))
    if not hashes:
        raise Hold("候補のCAB全体のSHA-256またはSHA-512を確認できません。")
    return hashes


def same_cab(left, right):
    common = left.keys() & right.keys()
    return bool(common) and all(left[algorithm] == right[algorithm] for algorithm in common)


def fwupd_bindings():
    try:
        import gi
        gi.require_version("Fwupd", "2.0")
        from gi.repository import Fwupd, GLib
    except (ImportError, ValueError) as exc:
        raise Hold("更新候補の照会・検証には python3-gi と gir1.2-fwupd-2.0 が必要です。") from exc
    return Fwupd, GLib


def fwupd_query(operation, argument):
    Fwupd, GLib = fwupd_bindings()
    # 適用時に対話モードの fwupdmgr local-install が処理する操作を、照会接続にも伝える。
    flags = reduce(operator.or_, (getattr(Fwupd.FeatureFlags, name.upper().replace("-", "_"))
                                  for name in CLIENT_FEATURES))
    client = Fwupd.Client.new()
    try:
        if not client.set_feature_flags(flags, None):
            raise Hold("fwupdに対話操作の機能を登録できません。")
    except GLib.Error as exc:
        raise Hold("fwupdに対話操作の機能を登録できません。 " + visible(exc.message)) from exc
    try:
        items = getattr(client, operation)(argument, None)
        result = [json.loads(item.to_json_string(Fwupd.CodecFlags.NONE)) for item in items]
    except GLib.Error as exc:
        if (operation == "get_upgrades" and exc.domain == "FwupdError"
                and exc.code == Fwupd.Error.NOTHING_TO_DO):
            return []
        raise Hold("fwupdの照会が成立しません。 " + visible(exc.message)) from exc
    if not all(isinstance(item, dict) for item in result):
        raise Error("fwupdの照会結果を解釈できません。")
    return result


def version_key(version, fmt):
    """fwupd 2.0の版比較に従って、比較可能な値にする。"""
    if not isinstance(version, str) or not version:
        raise Hold("fwupdの版番号を比較できません。")
    if fmt == "plain":
        return version
    if fmt == "hex" and re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", version):
        is_date = len(version) == 8 and version.startswith("20")
        value = int(version, 16 if version.startswith("0x") else 10)
        if not is_date and 0 < value <= 0xffffffff:
            version = f"0x{value:08x}"
    parts = []
    for part in version.split("."):
        match = re.match(r"[ \t\r\n\f\v]*[+-]?[0-9]+", part)
        number, suffix = (int(match[0]), part[match.end():]) if match else (0, part)
        # fwupdでは ~ が接尾部の終端より先になる。
        parts.append((number, tuple(-1 if ch == "~" else ord(ch) for ch in suffix) + (0,)))
    return tuple(parts)


def candidate(device, *, releases=None, remote_id=REMOTE):
    if releases is None:
        releases = fwupd_query("get_upgrades", device["DeviceId"])
    branch = device.get("Branch") or "default"
    eligible = [r for r in releases if r.get("RemoteId") == remote_id
                and (r.get("Branch") or "default") == branch
                and not {"blocked-approval", "blocked-version", "is-alternate-branch",
                         "is-downgrade"}.intersection(strings(r, "Flags"))]
    if not eligible:
        return None
    # GetUpgradesは機器のVersionFormatで新しい順に返す。表示文字列を辞書順にしない。
    release = eligible[0]
    fmt = device.get("VersionFormat")
    version = version_key(release.get("Version"), fmt)
    if version == version_key(device["Version"], fmt) or not release.get("AppstreamId"):
        raise Hold("目標版または更新コンポーネントを特定できません。")
    hashes = release_hashes(release)
    for other in eligible[1:]:
        if version_key(other.get("Version"), fmt) != version:
            continue
        other_hashes = release_hashes(other)
        if other.get("AppstreamId") != release["AppstreamId"] or not same_cab(hashes, other_hashes):
            raise Hold("同じ版に異なる配布物があります。更新を一つに絞れません。")
        hashes.update(other_hashes)
    return release


class CatalogRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Hold("安定版カタログの取得先が転送されました。直接取得できるURIを確認してください。")


def download_catalog_file(opener, uri, limit):
    try:
        request = Request(uri, headers={"User-Agent": "mknk-bios-update/1.0"})
        with opener.open(request, timeout=60) as stream:
            content = stream.read(limit + 1)
    except (OSError, HTTPException, ValueError) as exc:
        raise Hold("LVFSの安定版カタログを取得できません。 " + visible(exc)) from exc
    if not content or len(content) > limit:
        raise Hold("LVFSの安定版カタログまたは署名のサイズを確認できません。")
    return content


def verify_catalog_signature(metadata, signature):
    Fwupd, GLib = fwupd_bindings()
    client = Fwupd.Client.new()
    try:
        if not client.update_metadata_bytes(REMOTE, GLib.Bytes.new(metadata), GLib.Bytes.new(signature), None):
            raise Hold("fwupdで安定版カタログの署名を確認できません。")
    except GLib.Error as exc:
        # fwupd 2.0.20は、この組の署名・チェックサムを検証した後に同一署名時刻を返す。
        # 索引が同じカタログに由来するとは仮定せず、候補を検証済みXMLに照合する。
        if not (exc.domain == "FwupdError" and exc.code == Fwupd.Error.NOTHING_TO_DO):
            raise Hold("fwupdで安定版カタログの署名を確認できません。 " + visible(exc.message)) from exc
    return client.get_daemon_version()


def catalog_blocks(content):
    if content.startswith(b"\x28\xb5\x2f\xfd"):
        yield from zstd_catalog_blocks(content)
        return
    if content.startswith(b"\xfd7zXZ\x00"):
        open_compressed = lzma.open
    elif content.startswith(b"\x1f\x8b"):
        open_compressed = gzip.open
    else:
        yield content
        return
    with open_compressed(io.BytesIO(content)) as stream:
        yield from iter(lambda: stream.read(65536), b"")


def component_guids(component):
    return {node.text.strip().lower() for node in component.findall("provides/firmware[@type='flashed']")
            if node.text}


def read_catalog_components(metadata, guids, *, digest=None):
    parser = ET.XMLPullParser(events=("end",))
    components = []
    decoded_size = 0
    try:
        for block in catalog_blocks(metadata):
            decoded_size += len(block)
            if decoded_size > METADATA_XML_LIMIT:
                raise Hold("展開したLVFS安定版カタログが大きすぎます。")
            if digest is not None:
                digest.update(block)
            parser.feed(block)
            for _, element in parser.read_events():
                if element.tag != "component":
                    continue
                if guids.intersection(component_guids(element)):
                    components.append(element)
                else:
                    element.clear()
        parser.close()
    except (ET.ParseError, lzma.LZMAError, OSError, EOFError) as exc:
        raise Hold("署名済みのLVFS安定版カタログを読み取れません。") from exc
    return components


def load_stable_catalog(remote, settings, guid, device):
    uri = remote["MetadataUri"]
    signature_uri = remote.get("MetadataUriSig")
    if signature_uri != uri + ".jcat":
        raise Hold("承認済みカタログに対応する署名URIを確認できません。")
    opener = build_opener(CatalogRedirectHandler())
    signature = download_catalog_file(opener, signature_uri, METADATA_SIG_LIMIT)
    metadata = download_catalog_file(opener, uri, METADATA_LIMIT)
    compare_remote(remote, stable_remote(settings))
    daemon_version = verify_catalog_signature(metadata, signature)
    guids = {value.lower() for value in strings(device, "Guid")}
    guids.add(guid)
    return read_catalog_components(metadata, guids), daemon_version


def catalog_cab_artifact(release):
    artifact = release.find("artifacts/artifact[@type='binary']")
    if artifact is not None and catalog_artifact_is_cab(artifact):
        return artifact
    return None


def catalog_artifact_is_cab(artifact):
    filename = artifact.findtext("filename")
    return filename is None or filename.lower().endswith(".cab")


def catalog_checksum_values(nodes):
    return {node.text.strip().lower() for node in nodes if node.text}


def catalog_cab(release):
    primary = catalog_cab_artifact(release)
    legacy = catalog_checksum_values(release.findall("checksum[@target='container']"))
    hashes = catalog_checksum_values(primary.findall("checksum")) if primary is not None else set()
    matching = [primary] if primary is not None else []
    aliases = [(artifact, catalog_checksum_values(artifact.findall("checksum")))
               for artifact in release.findall("artifacts/artifact[@type='binary']")
               if artifact is not primary and catalog_artifact_is_cab(artifact)]
    if not hashes:
        hashes = legacy
    elif legacy:
        aliases.append((None, legacy))

    # 別方式のハッシュが同じCABを結ぶ場合も、後続の記載を照合に含める。
    while True:
        digests = set(strong_hashes(hashes).values())
        unlinked = []
        for artifact, values in aliases:
            if digests.isdisjoint(values):
                unlinked.append((artifact, values))
            else:
                hashes.update(values)
                if artifact is not None:
                    matching.append(artifact)
        if len(unlinked) == len(aliases):
            return hashes, matching
        aliases = unlinked


def release_version_matches(raw, version, fmt):
    if not raw:
        return False
    if version_key(raw, fmt) == version_key(version, fmt):
        return True
    try:
        return version_key(esrt_version(raw, fmt), fmt) == version_key(version, fmt)
    except Hold:
        return False


def catalog_version(raw, fmt):
    # UEFIカプセル機器では、ドットのないカタログ版をESRTの整数版として解釈する。
    return esrt_version(raw, fmt) if raw and "." not in raw else raw


def host_hardware_ids():
    try:
        ids = json.loads(command(["hwids"]))
    except (Error, OSError, ValueError):
        return None
    if not isinstance(ids, dict) or not all(isinstance(value, str) for value in ids.values()):
        return None
    # fwupdmgrはSMBIOSの属性値と、属性の組から得たCHIDを同じオブジェクトで返す。
    hardware_ids = {value for value in ids.values() if GUID_TEXT.fullmatch(value)}
    return hardware_ids or None


def catalog_requirements(element):
    # 通常のfwupd更新では推奨条件も適用される。
    return [node for tag in ("requires", "recommends", "suggests")
            for node in element.findall(f"{tag}/*")]


def catalog_model_requirement(node):
    return (node.tag in ("hardware", "not_hardware")
            or (node.tag == "firmware" and (node.text or "").strip() == "vendor-id"))


def catalog_vendor_matches(node, device):
    pattern = node.get("version")
    vendor_ids = device.get("VendorIds")
    if (len(node) or set(node.attrib) - {"compare", "version"} or not pattern
            or not isinstance(vendor_ids, list) or not vendor_ids
            or any(not isinstance(value, str) or not value.strip() or "\0" in value for value in vendor_ids)):
        return None
    # fwupdはcompare属性にかかわらず、連結したVendorIdsをGLibの正規表現で照合する。
    _, GLib = fwupd_bindings()
    try:
        regex = GLib.Regex.new(pattern, 0, 0)
        return regex.match("|".join(vendor_ids), 0)[0] if regex is not None else None
    except GLib.Error:
        return None


def catalog_model_matches(requirements, device, hardware_ids, *, emulated):
    matches = True
    for node in requirements:
        if node.tag == "firmware":
            vendor_matches = catalog_vendor_matches(node, device)
            if vendor_matches is False:
                return False
            if vendor_matches is None:
                matches = None
            continue
        if node.tag == "not_hardware":
            matches = None
            continue
        alternatives = (node.text or "").strip().split("|")
        if node.attrib or len(node) or not all(GUID_TEXT.fullmatch(value) for value in alternatives):
            matches = None
            continue
        if emulated:
            continue
        ids = hardware_ids()
        if ids is None:
            matches = None
        elif set(alternatives).isdisjoint(ids):
            return False
    return matches


def catalog_requirement_matches(node, device, devices, daemon_version, client_features=CLIENT_FEATURES):
    """評価できない必須条件には None を返す。"""
    if len(node):
        return None
    text = (node.text or "").strip()
    if node.tag == "client" and not node.attrib:
        return True if set(text.split("|")).issubset(client_features) else None
    compare = VERSION_COMPARISONS.get(node.get("compare"))
    if compare is None or set(node.attrib) != {"compare", "version"}:
        return None
    if node.tag == "firmware":
        target = device
        if text:
            alternatives = text.lower().split("|")
            if not all(GUID_TEXT.fullmatch(guid) for guid in alternatives):
                return None
            target = None
            for guid in alternatives:
                matches = [peer for peer in devices if guid in {value.lower() for value in strings(peer, "Guid")}]
                if matches:
                    if len(matches) == 1:
                        target = matches[0]
                    break
            if target is None:
                return None
        actual, fmt = target.get("Version"), target.get("VersionFormat")
    elif node.tag == "id" and text == FWUPD_ID:
        actual, fmt = daemon_version, None
    else:
        return None
    required = node.get("version", "")
    version_pattern = (r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}" if fmt == "plain"
                       else r"(?:[0-9]{1,18}(?:\.[0-9]{1,18})*|0x[0-9a-fA-F]{1,8})")
    if not actual or len(required) > 128 or not re.fullmatch(version_pattern, required):
        return None
    return compare(version_key(actual, fmt), version_key(required, fmt))


def missing_client_features(requirements, client_features=CLIENT_FEATURES):
    return sorted({feature for node in requirements if node.tag == "client" and not node.attrib and not len(node)
                   for feature in (node.text or "").strip().split("|")
                   if feature in UNSUPPORTED_CLIENT_FEATURES or feature in CLIENT_FEATURES and feature not in client_features})


def catalog_component_compatible(component, device):
    protocol = component.findtext("custom/value[@key='LVFS::UpdateProtocol']")
    if protocol is not None and protocol not in strings(device, "Protocols"):
        return False
    formats = {node.text for node in component.findall("custom/value[@key='LVFS::VersionFormat']")}
    if not formats:
        return True
    fmt = device.get("VersionFormat")
    # fwupd 2.0.20はBCD機器にpairのリリースも認める。
    return fmt not in (None, "", "unknown") and (fmt in formats or (fmt == "bcd" and "pair" in formats))


def catalog_download_size(entry, cab=None):
    artifact = catalog_cab_artifact(entry)
    size_path = "size[@type='download']"
    release_sizes = entry.findall(size_path)
    primary_sizes = artifact.findall(size_path) if artifact is not None else []
    binaries = entry.findall("artifacts/artifact[@type='binary']")
    hashes, matching_artifacts = catalog_cab(entry) if cab is None else cab
    artifact_sizes = [size for binary in matching_artifacts for size in binary.findall(size_path)]
    if not release_sizes and not artifact_sizes:
        return None
    size_error = "署名済みカタログのCABに受信サイズを一意に対応付けられません。"
    artifact_checksums = artifact.findall("checksum") if artifact is not None else []
    ambiguous = len(matching_artifacts) != len(binaries)
    if ((release_sizes and binaries and (artifact is None or ambiguous))
            or (primary_sizes and ambiguous and not artifact_checksums)):
        raise Hold(size_error)
    if artifact is not None and (release_sizes or (primary_sizes and not artifact_checksums)):
        # 階層をまたいで使う場合は、旧形式のCAB参照がbinary artifactと矛盾しないことを確認する。
        name = artifact.findtext("filename")
        for node in entry.findall("checksum[@target='container']"):
            other_name = node.get("filename")
            digest = (node.text or "").strip().lower()
            if ((name and other_name and other_name != name)
                    or any(len(digest) == len(value) and digest != value for value in hashes)):
                raise Hold(size_error)
    values = {(node.text or "").strip() for node in release_sizes + artifact_sizes}
    value = values.pop()
    if values or not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        raise Hold("署名済みカタログのCAB受信サイズを確認できません。")
    return int(value)


class CatalogCheck(NamedTuple):
    download_size: int | None
    model_listed: bool
    hashes: dict[str, str]
    unavailable: str | None


def require_catalog_release(components, device, devices, guid, release, remote, *, daemon_version,
                            verified_hashes=(), policy=None, client_features=CLIENT_FEATURES):
    fmt = device.get("VersionFormat")
    branch = device.get("Branch") or "default"
    current = version_key(device["Version"], fmt)
    target = version_key(release["Version"], fmt) if release else current
    index_hashes = release_hashes(release) if release else {}
    hardware_ids = cache(host_hardware_ids)
    flags = strings(device, "Flags")
    emulated = "emulated" in flags
    matched_hashes = set()
    sizes = set()
    candidate_mismatch = None
    model_listed = False
    uncertain_listing = False
    exclusions = []
    for component in components:
        same_branch = (component.findtext("branch") or "default") == branch
        esrt_matches = guid in component_guids(component)
        check_listing = release is None and esrt_matches
        if not (same_branch or check_listing):
            continue
        compatible = same_branch and catalog_component_compatible(component, device)
        component_requirements = catalog_requirements(component)
        missing_version_check = "version-check-required" in flags and not any(
            not node.text and not len(node) for node in component.findall("requires/firmware"))
        app_id = component.findtext("id")
        for entry in component.findall("releases/release"):
            raw = entry.get("version")
            candidate_version = (release and same_branch and esrt_matches and app_id == release["AppstreamId"]
                                 and release_version_matches(raw, release["Version"], fmt))
            try:
                display_version = catalog_version(raw, fmt) if same_branch else None
                version = version_key(display_version, fmt) if same_branch else None
            except Hold:
                version = None
            can_compete = same_branch and (version is None or (version >= target if release else version > current))
            if not (candidate_version or can_compete or check_listing):
                continue
            requirements = component_requirements + catalog_requirements(entry)
            model_requirements = [node for node in requirements if catalog_model_requirement(node)]
            model_matches = catalog_model_matches(model_requirements, device, hardware_ids, emulated=emulated)
            if model_matches is False:
                if candidate_version:
                    candidate_mismatch = "このBIOSは署名済みカタログにある更新候補の機種条件を満たしません。"
                continue
            if check_listing:
                model_listed |= model_matches is True
                uncertain_listing |= model_matches is None
            if not (candidate_version or can_compete):
                continue
            if not compatible:
                if candidate_version:
                    candidate_mismatch = "このBIOSは署名済みカタログの配布条件（更新プロトコル・版形式）を満たしません。"
                continue
            cab = catalog_cab(entry)
            hashes = cab[0]
            match = candidate_version and same_cab(index_hashes, strong_hashes(hashes))
            if not (match or can_compete):
                continue
            report_exclusion = not release and version is not None and esrt_matches and model_matches is True
            if missing_version_check:
                reason = "機器が要求する必須の版条件が署名済みカタログにありません。"
                if match:
                    raise Hold(reason)
                if report_exclusion:
                    exclusions.append((version, display_version, reason))
                continue
            evaluated = [(node, catalog_requirement_matches(node, device, devices, daemon_version, client_features))
                         for node in requirements if not catalog_model_requirement(node)]
            failed = [node for node, result in evaluated if result is False]
            if failed:
                if match:
                    raise Hold("このBIOSは署名済みカタログにある更新候補の必須条件を満たしません。")
                if report_exclusion:
                    node = failed[0]
                    required = visible(node.get("version"))
                    if node.tag == "firmware" and node.get("compare") == "ge":
                        reason = f"前提版 {required} 以上が必要です。"
                    else:
                        reason = f"必須の版条件（{node.get('compare')} {required}）を満たしていません。"
                    exclusions.append((version, display_version, reason))
                continue
            missing = missing_client_features((node for node, result in evaluated if result is None), client_features)
            client_reason = (f"必要なクライアント機能 {'、'.join(missing)} に対応する更新方法を確認してください。"
                             if missing else None)
            if match:
                if model_matches is None or any(result is None for _, result in evaluated):
                    raise Hold(client_reason or "署名済みカタログにある更新候補の必須条件を確認できません。")
                matched_hashes.update(hashes)
                size = catalog_download_size(entry, cab)
                if size is not None:
                    sizes.add(size)
                continue
            if hashes:
                if policy is None:
                    policy = admin_checksums(remote)
                reason = admin_policy_reason(hashes, policy)
                if reason:
                    if report_exclusion:
                        exclusions.append((version, display_version, reason))
                    continue
            if client_reason:
                raise Hold(client_reason + f" 対象版 {visible(display_version if version is not None else raw)}")
            if version is None:
                raise Hold("署名済みカタログに、版を比較できない候補があります。")
            if release and version == target:
                raise Hold("署名済みカタログに同じ版の別の配布物があります。適用範囲を確定できません。")
            raise Hold("署名済みカタログに、適合を除外できない上位版があります。 " + visible(raw))
    if release:
        if not matched_hashes:
            raise Hold(candidate_mismatch or
                       "このBIOS更新候補の版とCABハッシュを、署名済みのLVFS安定版カタログで確認できません。")
        if policy is None:
            policy = admin_checksums(remote)
        other_block_hashes = set(index_hashes.values()).union(verified_hashes)
        reason = admin_policy_reason(matched_hashes, policy, other_block_hashes=other_block_hashes)
        if reason:
            raise Hold(reason)
    elif not model_listed and uncertain_listing:
        raise Hold("署名済みカタログにある機種の必須条件を確認できません。")
    if len(sizes) > 1:
        raise Hold("署名済みカタログで同じCABの受信サイズが一致しません。")
    signed_hashes = strong_hashes(matched_hashes)
    if release and not same_cab(index_hashes, signed_hashes):
        raise Hold("fwupdと署名済みカタログのCABハッシュが一致しません。")
    newest = max(exclusions, key=lambda exclusion: exclusion[0], default=None)
    unavailable = f"新版 {visible(newest[1])}　{newest[2]}" if newest else None
    return CatalogCheck(next(iter(sizes), None), model_listed, signed_hashes, unavailable)


def admin_policy_reason(hashes, policy, *, other_block_hashes=()):
    # GetUpgradesは現在のfwupdの配布制限を適用する。ローカルCABの送信直前にも確認する。
    approved, blocked = policy
    if not blocked.isdisjoint(hashes) or not blocked.isdisjoint(other_block_hashes):
        return "明示ブロック対象のCABです。"
    if approved is not None and hashes.isdisjoint(approved):
        return "承認一覧にこのCABがありません。"
    return None


def admin_checksums(remote):
    approved = checksum_list("get-approved-firmware") if remote.get("ApprovalRequired") is True else None
    # 個別ブロック一覧のCLIは2.0系にあり、2.1.1以降で廃止された。
    help_text = subprocess.run([FWUPDMGR, "--help"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, errors="replace", check=True).stdout
    blocked = (checksum_list("get-blocked-firmware")
               if re.search(r"(?m)^\s*get-blocked-firmware(?:\s|$)", help_text) else set())
    return approved, blocked


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
        elif kind and kind != "Battery" and power_field(item, "online") in ("1", "2"):
            supplied = True
    if battery and not supplied:
        raise Hold("内蔵バッテリーを検出しましたが、外部給電を確認できません。ACアダプターを接続してください。")


def power_field(item, name):
    try:
        return (item / name).read_text().strip()
    except FileNotFoundError:
        return ""


class MountPoint(NamedTuple):
    mount_id: int
    device: str
    root: str
    filesystem: str
    read_only: bool


def mount_points():
    mounts = {}
    for line in MOUNTINFO.read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        filesystem, _, super_options = after.split(maxsplit=2)
        location = re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), fields[4])
        read_only = "ro" in fields[5].split(",") or "ro" in super_options.split(",")
        mounts[location] = MountPoint(int(fields[0]), fields[2], fields[3], filesystem, read_only)
    return mounts


def require_efivarfs(mounts, *, writable=False):
    mount = mounts.get(str(EFIVARS))
    if mount is None or (mount.root, mount.filesystem) != ("/", "efivarfs"):
        raise Hold("EFI変数領域（efivarfs）のマウントを確認できません。")
    if writable and mount.read_only:
        raise Hold("EFI変数領域（efivarfs）が読み取り専用です。予約には変数の書き込みが必要です。")


def mounted_path_identity(path):
    # O_PATHならrootだけが区画を読めるVFATでも、開いたディレクトリのマウントを特定できる。
    try:
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            device = os.fstat(fd).st_dev
            fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
        finally:
            os.close(fd)
    except OSError as exc:
        raise Hold("配送区画の実際のマウントを確認できません。") from exc
    mount_id = re.search(r"(?m)^mnt_id:[ \t]*([0-9]+)$", fdinfo)
    if mount_id is None:
        raise Hold("配送区画の実際のマウントIDを確認できません。")
    return f"{os.major(device)}:{os.minor(device)}", int(mount_id[1])


def udisks_objects():
    try:
        from gi.repository import Gio, GLib
    except ImportError as exc:
        raise Hold("配送区画を照合するには python3-gi とUDisks2が必要です。") from exc
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        result = bus.call_sync(UDISKS, "/org/freedesktop/UDisks2",
                               "org.freedesktop.DBus.ObjectManager", "GetManagedObjects",
                               None, GLib.VariantType.new("(a{oa{sa{sv}}})"),
                               Gio.DBusCallFlags.NONE, 5000, None)
        return result.unpack()[0]
    except GLib.Error as exc:
        raise Hold("UDisks2でEFIの配送区画を照会できません。 " + visible(exc.message)) from exc


def possible_delivery_volumes(objects):
    # fwupd 2.0.20の候補を含む。回復区画の名前による除外には依存しない。
    for interfaces in objects.values():
        block = interfaces.get(UDISKS + ".Block", {})
        if block.get("IdType") != "vfat":
            continue
        partition = interfaces.get(UDISKS + ".Partition", {})
        kind = partition.get("Type", "").lower()
        mdraid = block.get("MDRaid", "/") != "/"
        internal_bdp = (block.get("HintSystem") is True
                        and kind in (BDP_TYPE, "0x0b", "0x06", "vfat", "fat32", "fat32lba"))
        if mdraid or internal_bdp or kind in (ESP_TYPE, "0xef", "efi"):
            yield block, partition, interfaces.get(UDISKS + ".Filesystem", {})


def find_esp(mounts):
    p = subprocess.run([LSBLK, "--json", "--list", "--output", "MAJ:MIN,PARTTYPE,PARTUUID"],
                       capture_output=True, text=True, check=True)
    try:
        devices = json.loads(p.stdout)["blockdevices"]
    except (ValueError, TypeError, KeyError) as exc:
        raise Hold("接続中の物理区画を読み取れません。") from exc
    if not isinstance(devices, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("maj:min"), str) for row in devices):
        raise Hold("接続中の物理区画の識別子を読み取れません。")
    parts = {row["maj:min"]: row.get("partuuid") for row in devices
             if str(row.get("parttype", "")).lower() == ESP_TYPE}
    if len(parts) != 1:
        raise Hold(f"GPTのEFIシステム区画を{len(parts)}件検出しました。更新先を一つに確定できません。")
    number, partition_id = parts.popitem()
    try:
        esp_guid = str(uuid.UUID(partition_id or ""))
    except ValueError as exc:
        raise Hold("EFIシステム区画の区画GUIDを確認できません。") from exc
    matching = {row["maj:min"] for row in devices if str(row.get("partuuid", "")).lower() == esp_guid}
    if matching != {number}:
        raise Hold("EFIシステム区画の区画GUIDが接続中の複数の区画と一致します。")
    volumes = list(possible_delivery_volumes(udisks_objects()))
    if len(volumes) != 1:
        raise Hold(f"fwupdの候補になり得る配送区画を{len(volumes)}件検出しました。")
    block, partition, filesystem = volumes[0]
    try:
        devnum = block["DeviceNumber"]
        identity = f"{os.major(devnum)}:{os.minor(devnum)}"
        mount = Path(os.fsdecode(bytes(filesystem["MountPoints"][0]).removesuffix(b"\0")))
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise Hold("UDisks2の配送区画の識別子またはマウント先を確認できません。") from exc
    if partition.get("UUID", "").lower() != esp_guid or identity != number:
        raise Hold("UDisks2の配送区画とGPTのEFIシステム区画が一致しません。")
    entry = mounts.get(str(mount))
    if mount not in ESP_MOUNTS or entry is None or (entry.device, entry.root, entry.filesystem) != (number, "/", "vfat"):
        raise Hold("配送区画のマウント先を /boot/efi、/efi、/boot のいずれにも照合できません。")
    if mounted_path_identity(mount) != (number, entry.mount_id):
        raise Hold("配送区画のパスが照合したマウントを指していません。")
    if any(other != str(mount) and Path(other).is_relative_to(mount) for other in mounts):
        raise Hold("配送区画の下に別のマウントがあり、配置先を照合できません。")
    return mount, esp_guid


def esp_has_entry(mount, relative, *, directory):
    try:
        path = mount
        # VFATのマウントオプションにかかわらず、EFIと同じように名前の大小文字を区別しない。
        for part in Path(relative).parts:
            matches = [item for item in path.iterdir() if item.name.casefold() == part.casefold()]
            if not matches:
                return False
            if len(matches) > 1:
                raise Hold("EFI起動区画のパスが複数の項目に一致します。 " + visible(relative))
            path = matches[0]
        if directory:
            return next(path.iterdir(), None) is not None
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        # 既知のマウント位置だけを読み取り、未作成と読取不能を区別する。
        path = mount / relative
        match = path / "*" if directory else path
        depth = len(match.relative_to(mount).parts)
        args = ["/usr/bin/find", "-P", str(mount), "-xdev", "-maxdepth", str(depth),
                "-ipath", str(match), "-printf", "x", "-quit"]
        return bool(sudo_command(args, "EFI起動区画の既存更新ファイル確認"))


def disk_entries(mount):
    return [path for path, directory in DISK_DELIVERY_PATHS
            if esp_has_entry(mount, path, directory=directory)]


def read_efi_variable(path):
    try:
        return path.read_bytes()
    except PermissionError:
        return sudo_command(["/usr/bin/cat", "--", str(path)], "EFI変数の読み取り")


def efi_variable_payload(name, namespace, *, size=None):
    try:
        data = read_efi_variable(EFIVARS / f"{name}-{namespace}")
    except FileNotFoundError:
        return None
    payload = data[4:]
    if not payload or (size is not None and len(payload) != size):
        raise Hold(f"EFI変数 {name} の内容を確認できません。")
    return payload


def boot_load_option(data):
    # efivarfs属性4バイト、EFI_LOAD_OPTIONの属性4バイト、デバイスパス長2バイト。
    for end in range(10, len(data) - 1, 2):
        if data[end:end + 2] != b"\0\0":
            continue
        start = end + 2
        length = int.from_bytes(data[8:10], "little")
        if start + length <= len(data):
            try:
                return data[10:end].decode("utf-16-le"), data[start:start + length]
            except UnicodeDecodeError:
                break
        break
    raise Hold("既存のEFI起動登録の内容を解釈できません。")


def check_boot_entries(esp_guid, profile):
    allowed = profile.get("boot_entry_sha256", [])
    if not isinstance(allowed, list):
        raise Hold("検証済みのEFI起動登録の一覧を読み取れません。")
    pattern = re.compile(r"Boot[0-9a-f]{4}-" + EFI_GLOBAL, re.IGNORECASE)
    for variable in EFIVARS.iterdir():
        if not pattern.fullmatch(variable.name):
            continue
        data = read_efi_variable(variable)
        description, path = boot_load_option(data)
        if description not in ("Linux Firmware Updater", "Linux-Firmware-Updater"):
            continue
        # GPTの短縮HD()パスで、現物のESPと一致し、ローダーと引数を含む全バイトを照合できる場合だけ再利用する。
        if (path[:4] != b"\x04\x01\x2a\x00" or path[40:42] != b"\x02\x02"
                or str(uuid.UUID(bytes_le=path[24:40])) != esp_guid
                or hashlib.sha256(data).hexdigest() not in allowed):
            raise Hold(f"{variable.name[:8]} の更新用起動登録をこのOSのものと確認できません。")


def partition_number(device):
    try:
        number = int((Path("/sys/dev/block") / device / "partition").read_text(encoding="ascii"))
    except (OSError, ValueError) as exc:
        raise Hold("ESPのGPT区画番号を確認できません。") from exc
    if number < 1:
        raise Hold("ESPのGPT区画番号を確認できません。")
    return number


def boot_disk_partition(path):
    offset = 0
    partition = None
    while offset + 4 <= len(path):
        kind, subtype, length = struct.unpack_from("<BBH", path, offset)
        end = offset + length
        if length < 4 or end > len(path):
            return None
        if kind == 0x7f:
            # 複数のデバイスパスを持つ項目では配送先を確定しない。
            return partition if subtype == 0xff and length == 4 and end == len(path) else None
        if partition is not None and (kind, subtype) != (4, 4):
            return None
        if (kind, subtype) == (4, 1):
            if length != 42 or path[offset + 40:end] != b"\x02\x02":
                return None
            guid = str(uuid.UUID(bytes_le=path[offset + 24:offset + 40]))
            number = struct.unpack_from("<I", path, offset + 4)[0]
            partition = guid, number, offset == 0
        offset = end
    return None


def check_disk_boot_target(esp_guid, esp_device):
    order = efi_variable_payload("BootOrder", EFI_GLOBAL)
    if order is None or len(order) % 2:
        raise Hold("ディスク配送先を確認するためのBootOrderを読み取れません。")
    for (index,) in struct.iter_unpack("<H", order):
        name = f"Boot{index:04X}"
        try:
            data = read_efi_variable(EFIVARS / f"{name}-{EFI_GLOBAL}")
        except FileNotFoundError as exc:
            raise Hold(f"BootOrderの {name} を確認できません。") from exc
        _, path = boot_load_option(data)
        attributes = int.from_bytes(data[4:8], "little")
        if not attributes & 1 or attributes & 0x1f00:
            continue  # 無効な項目や通常起動の対象外の項目は選ばれない。
        partition = boot_disk_partition(path)
        if partition is not None and partition[:2] == (esp_guid, partition_number(esp_device)):
            if partition[2] or efi_variable_payload("BootCurrent", EFI_GLOBAL, size=2) == struct.pack("<H", index):
                return
        raise Hold(f"BootOrderで最初に有効な {name} の起動先が配送区画に一致しません。")
    raise Hold("BootOrderに通常起動用の有効な項目がありません。")


def is_x64_efi_application(stream, size):
    dos = stream.read(64)
    if len(dos) != 64 or dos[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", dos, 60)[0]
    if not 64 <= offset <= size - 94:
        return False
    stream.seek(offset)
    header = stream.read(94)
    if len(header) != 94:
        return False
    signature, machine, sections, _, _, _, optional_size, flags = struct.unpack_from("<4sHHIIIHH", header)
    magic = struct.unpack_from("<H", header, 24)[0]
    subsystem = struct.unpack_from("<H", header, 24 + 68)[0]
    return (signature == b"PE\0\0" and machine == 0x8664 and magic == 0x20b and subsystem == 10
            and flags & 2 and optional_size >= 112 and sections > 0
            and offset + 24 + optional_size + sections * 40 <= size)


def efi_asset_sha256(path, *, esp=None, check_application=False):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not info.st_size:
                raise Hold(f"EFI起動ファイルを確認できません。 {path.name}")
            if check_application:
                if not is_x64_efi_application(stream, info.st_size):
                    raise Hold(f"x64のEFIアプリケーションとして確認できません。 {path.name}")
                stream.seek(0)
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        if esp is None:
            raise
        if not esp_has_entry(esp, path.relative_to(esp), directory=False):
            return None
        output = sudo_command(["/usr/bin/sha256sum", "--", str(path)], "ESPのshimの読み取り")
        if re.match(rb"[0-9a-f]{64} ", output):
            return output[:64].decode("ascii")
        raise Hold("ESPのshimのハッシュを確認できません。")


def check_boot_delivery(esp, esp_guid, esp_device, profile, *, bootloader_capability):
    try:
        secure_boot = efi_variable_payload("SecureBoot", EFI_GLOBAL, size=1)
    except OSError as exc:
        raise Hold("Secure Bootの有効状態を確認できません。") from exc
    if secure_boot not in (b"\x00", b"\x01"):
        raise Hold("Secure Bootの有効状態を確認できません。")
    enabled = secure_boot == b"\x01"

    boot = profile.get("secure_boot", {})
    if not isinstance(boot, dict):
        raise Hold("Secure Bootの機種別対応情報を確認できません。")
    delivery = boot.get("delivery")
    if "delivery" in boot and delivery not in ("capsule-on-disk", "shim", "nvram"):
        raise Hold("機種別対応情報のEFI配送方式を確認できません。")
    if delivery in (None, "capsule-on-disk"):
        supported = efi_variable_payload("OsIndicationsSupported", EFI_GLOBAL, size=8)
        disk_supported = supported is not None and bool(int.from_bytes(supported, "little") & 4)
        if delivery == "capsule-on-disk":
            if not disk_supported:
                raise Hold("機種別対応情報のディスク配送方式をOsIndicationsSupportedに照合できません。")
            check_disk_boot_target(esp_guid, esp_device)
            return enabled
        if disk_supported:
            raise Hold("ディスク配送に対応しています。機種別対応情報に検証済みの配送方式を指定してください。")
    if bootloader_capability is not None:
        if bootloader_capability.value:
            raise Hold("ブートローダーが更新に対応すると通知しています。検証済みの配送方式を確認できません。")
        if bootloader_capability.attributes & 1:
            raise Hold("不揮発のBootloaderSupportsFwupdをfwupd-efi 1.4が更新登録として扱うため、NVRAM配送を保留します。")
    if enabled and delivery != "shim":
        raise Hold("Secure Bootが有効です。検証済みの配送方式と起動ファイルを機種別対応情報に設定してください。")
    try:
        platform_size = EFI_PLATFORM_SIZE.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise Hold("fwupdのEFIローダーに必要なUEFIのビット数を確認できません。") from exc
    if platform_size != "64":
        raise Hold("このサンプルのNVRAM配送は64ビットUEFIのfwupdローダーを使用します。")

    directory = boot.get("efi_app_dir", None if enabled else str(EFI_APP_DIR))
    if not isinstance(directory, str) or not Path(directory).is_absolute():
        raise Hold("fwupd配布パッケージのEFI配置先を確認できません。")
    package = Path(directory)
    if not enabled:
        # fwupdはSecure Boot無効時は、署名なしのファイルが存在すれば先に採用する。
        loader = efi_asset_sha256(package / "fwupdx64.efi", check_application=True)
        hash_key = "fwupd_efi_unsigned_sha256"
        if loader is None:
            loader = efi_asset_sha256(package / "fwupdx64.efi.signed", check_application=True)
            hash_key = "fwupd_efi_sha256"
        if not loader or (hash_key in boot and loader != boot[hash_key]):
            raise Hold("NVRAM配送用のfwupdx64.efiローダーを確認できません。")
        return enabled

    vendor = boot.get("esp_vendor_dir")
    if not isinstance(vendor, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", vendor):
        raise Hold("fwupdが使うESP上のディレクトリを確認できません。")
    loader = efi_asset_sha256(package / "fwupdx64.efi.signed")
    if not loader or loader != boot.get("fwupd_efi_sha256"):
        raise Hold("Secure Boot用の検証済みfwupd EFIローダーを確認できません。")
    packaged = efi_asset_sha256(package / "shimx64.efi.signed")
    installed = efi_asset_sha256(esp / "EFI" / vendor / "shimx64.efi", esp=esp)
    allowed = boot.get("shim_sha256")
    chosen = packaged or installed
    if not chosen or not isinstance(allowed, list) or chosen not in allowed:
        raise Hold("Secure Boot用の検証済みshimがESPにもfwupdの配布物にも用意できません。")
    if packaged and packaged != installed:
        # fwupd checks the copy against SbatLevelRT when the package differs from the ESP.
        sbat = efi_variable_payload("SbatLevelRT", EFI_SHIM)
        digest = hashlib.sha256(sbat).hexdigest() if sbat is not None else None
        if "shim_copy_sbat_sha256" not in boot or digest != boot["shim_copy_sbat_sha256"]:
            raise Hold("shimのコピー先で検証したSBAT設定を現在のSbatLevelRTに照合できません。")
    return enabled


def valid_update_device_path(path):
    offset = 0
    file_path = False
    while offset + 4 <= len(path):
        kind, subtype, size = struct.unpack_from("<BBH", path, offset)
        end = offset + size
        if size < 4 or end > len(path):
            return False
        if kind == 0x7f:
            if size != 4 or not file_path:
                return False
            if subtype == 0xff:
                return end == len(path)
            if subtype != 1:
                return False
            file_path = False
        elif (kind, subtype) == (4, 4):
            name = path[offset + 4:end]
            if not 6 < len(name) <= 2048:
                return False
            try:
                decoded = name.decode("utf-16-le")
            except UnicodeDecodeError:
                return False
            if len(decoded) < 2 or not decoded.endswith("\0") or "\0" in decoded[:-1]:
                return False
            file_path = True
        offset = end
    return False


class BootloaderCapability(NamedTuple):
    value: int
    attributes: int


def fwupd_efi_state():
    # fwupd-efi v1.4のFWUP_UPDATE_INFO v7、先頭4バイトはefivarfsの属性。
    pending = []
    bootloader_capability = None
    for var in EFIVARS.iterdir():
        if not var.name.lower().endswith("-" + FWUPDATE_GUID):
            continue
        name = var.name[:-(len(FWUPDATE_GUID) + 1)]
        if name in ("FWUPDATE_VERBOSE", "FWUPDATE_DEBUG_LOG"):
            continue
        if name == "BootloaderSupportsFwupd":
            data = read_efi_variable(var)
            if bootloader_capability is not None or data[4:] not in (b"\x00", b"\x01"):
                raise Hold("EFI変数 BootloaderSupportsFwupd の内容を確認できません。")
            attributes, value = struct.unpack("<IB", data)
            bootloader_capability = BootloaderCapability(value, attributes)
            continue
        if not name.startswith("fwupd-"):
            raise Hold("fwupd用EFI名前空間に用途を確認できない既存登録があります。")
        data = read_efi_variable(var)
        if len(data) < 56 or int.from_bytes(data[4:8], "little") != 7:
            raise Hold("fwupd-efiの更新登録を解釈できません。")
        if not valid_update_device_path(data[56:]):
            raise Hold("fwupd-efiの更新登録のデバイスパスを確認できません。")
        status = int.from_bytes(data[52:56], "little")
        if status & 1:  # fwupd-efiが処理するATTEMPT_UPDATE
            pending.append(str(uuid.UUID(bytes_le=data[8:24])))
        elif status not in (0, 2):  # 結果クリア後とATTEMPTED
            raise Hold("fwupd-efiに状態を確定できない更新登録があります。")
    return pending, bootloader_capability


def boot_next():
    try:
        data = read_efi_variable(EFIVARS / f"BootNext-{EFI_GLOBAL}")
    except FileNotFoundError:
        return None
    if len(data) != 6:
        raise Hold("次回起動先（BootNext）を解釈できません。")
    return int.from_bytes(data[4:], "little")


def disk_delivery_requested():
    try:
        data = read_efi_variable(EFIVARS / f"OsIndications-{EFI_GLOBAL}")
    except FileNotFoundError:
        return False
    if len(data) != 12:
        raise Hold("ディスク経由カプセルの配送指示（OsIndications）を解釈できません。")
    return bool(int.from_bytes(data[4:], "little") & 4)


def check_ready(device, devices, history, settings):
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
    mounts = mount_points()
    require_efivarfs(mounts, writable=True)
    esp, esp_guid = find_esp(mounts)
    entries = disk_entries(esp)
    if entries:
        raise Hold("ESPの配送先に既存の項目があります。 " + "、".join(entries))
    pending, bootloader_capability = fwupd_efi_state()
    if pending:
        raise Hold("fwupd-efiに実行待ちの更新登録があります。")
    if boot_next() is not None:
        raise Hold("別の次回起動先（BootNext）が設定されています。その用途を確認してください。")
    check_boot_entries(esp_guid, settings)
    if disk_delivery_requested():
        raise Hold("既存のディスク経由カプセル配送指示があります。")
    secure_boot = check_boot_delivery(esp, esp_guid, mounts[str(esp)].device, settings,
                                      bootloader_capability=bootloader_capability)
    check_power()
    return esp, esp_guid, secure_boot, bootloader_capability


def cab_bases(settings):
    configured = settings.get("cab_base_uris", [])
    if not isinstance(configured, list):
        raise Hold("CABの許可済み配布先は cab_base_uris の配列で指定してください。")
    bases = [https_origin_path(url) for url in (*LVFS_CAB_BASE_URIS, *configured)]
    if not all(path.endswith("/") for _, _, path in bases):
        raise Hold("CABの許可済み配布先は / で終わるディレクトリURIで指定してください。")
    return bases


def require_cab_url(url, bases):
    host, port, path = https_origin_path(url)
    if not any(host == h and port == p and path.startswith(prefix) for h, p, prefix in bases):
        raise Hold("CABの取得先が許可されたHTTPSのホスト・ポート・パスの範囲外です。")


class CabRedirectHandler(HTTPRedirectHandler):
    def __init__(self, bases):
        self.bases = bases

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_cab_url(newurl, self.bases)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_302(self, req, fp, code, msg, headers):
        # urllibの標準処理は転送前に中間応答の本文を読み切る。
        with fp:
            location = headers.get("Location") or headers.get("URI")
            if not location:
                raise Hold("CABの転送先を確認できません。")
            redirected = self.redirect_request(req, fp, code, msg, headers, urljoin(req.full_url, location))
            visited = getattr(req, "cab_redirects", {req.full_url})
            if redirected.full_url in visited or len(visited) > self.max_redirections:
                raise Hold("CABの取得先が繰り返し転送されました。")
            redirected.cab_redirects = visited | {redirected.full_url}
        return self.parent.open(redirected, timeout=req.timeout)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def open_cabinet():
    try:
        fd = os.memfd_create("mknk-firmware.cab", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except (AttributeError, OSError) as exc:
        raise Hold("CABを固定するためにLinuxのmemfdが必要です。") from exc
    return os.fdopen(fd, "w+b")


def cabinet_path(fd):
    return f"/proc/self/fd/{fd}"


def seal_cabinet(cabinet, release):
    fd = cabinet.fileno()
    path = cabinet_path(fd)
    try:
        import fcntl

        cabinet.flush()
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        if not os.path.samestat(os.fstat(fd), os.stat(path)):
            raise Hold("固定したCABをプロセスのファイル記述子から読めません。")
    except (ImportError, AttributeError, OSError) as exc:
        raise Hold("CABを読み取り専用の内容として固定できません。") from exc

    verify_cabinet_hashes(cabinet, release_hashes(release))
    return path


def verify_cabinet_hashes(cabinet, hashes):
    for algorithm, expected in hashes.items():
        cabinet.seek(0)
        if hashlib.file_digest(cabinet, algorithm).hexdigest() != expected:
            raise Hold("ダウンロードしたCABのハッシュがLVFSの配布情報と一致しません。")


def fetch_cab(release, remote, cabinet, settings, *, download_size=None, opener=None):
    if download_size is not None and not 0 < download_size <= CAB_DOWNLOAD_LIMIT:
        raise Hold("署名済みカタログに記載されたCABの受信量が上限を超えています。")
    budget = CAB_DOWNLOAD_LIMIT
    bases = cab_bases(settings)
    if opener is None:
        opener = build_opener(CabRedirectHandler(bases))
    errors = []
    for location in strings(release, "Locations"):
        try:
            parsed = urlsplit(location)
            base = remote.get("FirmwareBaseUri")
            if parsed.scheme or parsed.netloc:
                url = location
            elif base:
                url = urljoin(base.rstrip("/") + "/", location.rsplit("/", 1)[-1])
            else:
                url = urljoin(remote["MetadataUri"], location)
            require_cab_url(url, bases)
        except (Hold, ValueError):
            continue
        if budget < (download_size or 1):
            raise Hold("CABの受信量が上限を超えました。")
        remaining = download_size if download_size is not None else budget
        try:
            req = Request(url, headers={"User-Agent": "mknk-bios-update/1.0"})
            with opener.open(req, timeout=60) as src:
                cabinet.seek(0)
                cabinet.truncate()
                while True:
                    requested = min(1024 * 1024, remaining + 1)
                    # 読み取りが途中で失敗した場合は、消費し得た分を受信枠に数える。
                    budget -= requested
                    chunk = src.read(requested)
                    budget += requested - len(chunk)
                    if not chunk or len(chunk) > remaining:
                        break
                    cabinet.write(chunk)
                    remaining -= len(chunk)
        except Hold as exc:
            errors.append(str(exc))
            continue
        except HTTPError as exc:
            exc.close()
            errors.append(f"HTTP {exc.code}")
            continue
        except (URLError, TimeoutError, ConnectionError, HTTPException, ValueError) as exc:
            if budget <= 0:
                raise Hold("CABの受信量が上限を超えました。") from exc
            errors.append(type(exc).__name__)
            continue
        if chunk:
            raise Hold("CABの受信量が上限を超えました。")
        if download_size is not None and remaining:
            raise Hold("CABの受信量が署名済みカタログのサイズと一致しません。")
        return seal_cabinet(cabinet, release)
    raise Error("CABを取得できません。 " + (errors[-1] if errors else "許可範囲内のHTTPS配布先がありません。"))


def archive_library(*formats):
    # libarchive.so.13はUbuntu 24.04のfwupdパッケージの依存ライブラリ。
    lib = ctypes.CDLL("libarchive.so.13")
    ptr = ctypes.c_void_p
    for name, result, args in (
        ("archive_read_new", ptr, []),
        ("archive_read_next_header", ctypes.c_int, [ptr, ctypes.POINTER(ptr)]),
        ("archive_read_data", ctypes.c_ssize_t, [ptr, ptr, ctypes.c_size_t]),
        ("archive_read_free", ctypes.c_int, [ptr]),
        *formats,
    ):
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = result, args
    return lib


def zstd_catalog_blocks(content):
    ptr = ctypes.c_void_p
    lib = archive_library(
        ("archive_read_support_format_raw", ctypes.c_int, [ptr]),
        ("archive_read_support_filter_zstd", ctypes.c_int, [ptr]),
        ("archive_read_open_memory", ctypes.c_int, [ptr, ctypes.c_char_p, ctypes.c_size_t]),
    )
    archive = lib.archive_read_new()
    if not archive:
        raise Error("カタログ展開用のメモリを確保できません。")
    try:
        entry = ptr()
        if (lib.archive_read_support_format_raw(archive) != 0
                or lib.archive_read_support_filter_zstd(archive) != 0
                or lib.archive_read_open_memory(archive, content, len(content)) != 0
                or lib.archive_read_next_header(archive, ctypes.byref(entry)) != 0):
            raise Hold("Zstandard形式の安定版カタログを開けません。")
        buf = ctypes.create_string_buffer(65536)
        while True:
            size = lib.archive_read_data(archive, buf, len(buf))
            if size == 0:
                return
            if size < 0:
                raise Hold("Zstandard形式の安定版カタログを展開できません。")
            yield buf.raw[:size]
    finally:
        lib.archive_read_free(archive)


def read_cab_files(path, payload_name=None):
    """照合済みCABからメタデータ、または指定されたペイロードだけを読み取る。"""
    ptr = ctypes.c_void_p
    lib = archive_library(
        ("archive_read_support_format_cab", ctypes.c_int, [ptr]),
        ("archive_read_open_filename", ctypes.c_int, [ptr, ctypes.c_char_p, ctypes.c_size_t]),
        ("archive_entry_pathname", ctypes.c_char_p, [ptr]),
    )
    archive = lib.archive_read_new()
    if not archive:
        raise Error("CAB解析用のメモリを確保できません。")
    files = {}
    seen = set()
    remaining = 2 * 1024 * 1024 if payload_name is None else 128 * 1024 * 1024
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
            name = os.fsdecode(lib.archive_entry_pathname(entry) or b"")
            name = name.replace("\\", "/").rsplit("/", 1)[-1]
            if not name or name in seen:
                raise Hold("CAB内のファイル名を一意に解決できません。")
            seen.add(name)
            selected = name.endswith(".metainfo.xml") if payload_name is None else name == payload_name
            if not selected:
                continue
            data = bytearray()
            while True:
                size = lib.archive_read_data(archive, buf, len(buf))
                if size == 0:
                    break
                if size < 0 or size > remaining:
                    raise Hold("CAB内の対象ファイルを上限内で読み取れません。")
                remaining -= size
                data.extend(buf.raw[:size])
            files[name] = data
    finally:
        lib.archive_read_free(archive)
    return files


def firmware_payload_name(release):
    # fwupd 2.0.20のFuCabinetはsource artifact、content checksum、既定名の順に解決する。
    source = release.find("artifacts/artifact[@type='source']")
    if source is not None:
        filename = source.findtext("filename")
    else:
        checksum = release.find("checksum[@target='content']")
        filename = checksum.get("filename") if checksum is not None else None
    if filename is None:
        return "firmware.bin"
    if not filename or filename != filename.strip() or "\\" in filename:
        raise Hold("CABのペイロードのファイル名を確定できません。")
    basename = filename.rsplit("/", 1)[-1]
    if basename in ("", ".", ".."):
        raise Hold("CABのペイロードのファイル名を確定できません。")
    return basename


def cab_manifest(path, app_id, *, single_component=False):
    components = []
    for data in read_cab_files(path).values():
        try:
            xml = ET.fromstring(data)
        except ET.ParseError as exc:
            raise Hold("CABのAppStreamメタデータを解釈できません。") from exc
        components.extend(node for node in xml.iter("component") if single_component or node.findtext("id") == app_id)
    if len(components) != 1 or components[0].findtext("id") != app_id:
        raise Hold("CAB内の署名対象と更新コンポーネントを一意に対応付けられません。")
    # GetDetailsと通常のInstallは最初のreleaseを使う。全版適用機器はcheck_readyで除外する。
    selected = components[0].find("releases/release")
    if selected is None or not selected.get("version"):
        raise Hold("CAB内の既定リリースと目標版を確認できません。")
    return firmware_payload_name(selected), selected.get("version")


def capsule_header_size(payload, offset):
    if len(payload) - offset < 28:
        raise Hold("UEFIカプセルのヘッダーが途切れています。")
    header_size, _, total_size = struct.unpack_from("<III", payload, offset + 16)
    if not 28 <= header_size <= total_size or total_size != len(payload) - offset:
        raise Hold("UEFIカプセルのヘッダーと実体のサイズが一致しません。")
    return header_size


def fmp_target(payload, guid):
    """標準FMPと、ESRT GUIDの外装が1つ付いた標準FMPを検査する。"""
    offset = 0
    esrt_guid = uuid.UUID(guid).bytes_le
    if payload.startswith(esrt_guid):
        offset = capsule_header_size(payload, 0)
        if payload.startswith(esrt_guid, offset):
            raise Hold("複数の外装が付いたUEFIカプセルは適用先を確定できません。")
    if not payload.startswith(FMP_CAPSULE, offset):
        return None
    body = offset + capsule_header_size(payload, offset)
    if len(payload) - body < 16:
        raise Hold("FMPカプセルの項目表を読み取れません。")
    version, drivers, images, image_offset = struct.unpack_from("<IHHQ", payload, body)
    if version != 1 or drivers != 0 or images != 1:
        raise Hold("FMPカプセルは対応形式で、ドライバーなし・更新画像1件に限ります。")
    image = body + image_offset
    if image_offset < 16 or len(payload) - image < 32:
        raise Hold("FMP画像の範囲を確定できません。")
    version, image_type, index, size, vendor_size = struct.unpack_from("<I16sB3xII", payload, image)
    header_size = {1: 32, 2: 40, 3: 48}.get(version)
    if header_size is None or index == 0 or size == 0 or header_size + size + vendor_size != len(payload) - image:
        raise Hold("FMP画像の形式、画像インデックス、サイズのいずれかを確定できません。")
    instance = struct.unpack_from("<Q", payload, image + 32)[0] if version >= 2 else 0
    return {"image_type_id": str(uuid.UUID(bytes_le=image_type)), "image_index": index,
            "hardware_instance": instance}


def check_capsule_scope(payload, guid, profile):
    target = fmp_target(payload, guid)
    if target is not None:
        verified = profile.get("fmp")
        if (verified != target or type(verified.get("image_index")) is not int
                or type(verified.get("hardware_instance")) is not int):
            raise Hold("FMP画像の種類・インデックス・インスタンスが検証済みのBIOS宛先と一致しません。")
        return "FMP画像1件"
    hashes = profile.get("vendor_payload_sha256", [])
    if isinstance(hashes, list) and hashlib.sha256(payload).hexdigest() in hashes:
        return "検証済みのメーカー形式（システムBIOS資源1件）"
    raise Hold("メーカー形式のカプセルと単一の書き込み先の対応を確認できません。")


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
    if fmt == "bcd":
        return ".".join(str((byte >> 4) * 10 + (byte & 0xf)) for byte in (a, b, c, d))
    parts = {"quad": (a, b, c, d), "triplet": (a, b, val & 0xffff),
             "pair": (val >> 16, val & 0xffff), "dell-bios": (b, c, d),
             "dell-bios-msb": (a, b, c)}
    if fmt not in parts:
        raise Hold("この機種のUEFI整数版の表示形式を照合できません。 " + visible(fmt))
    return ".".join(map(str, parts[fmt]))


def verify_cab(path, release, guid, device, devices, profile, *, parts=None, include_payload=False):
    if parts is None:
        parts = fwupd_query("get_details", str(path))
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
    if include_payload:
        payload_name, raw_version = cab_manifest(path, release["AppstreamId"], single_component=True)
    else:
        payload_name, raw_version = cab_manifest(path, release["AppstreamId"])
    version = content[0].get("Version")
    fmt = device.get("VersionFormat")
    if (not release_version_matches(raw_version, release["Version"], fmt)
            or (version and not release_version_matches(version, release["Version"], fmt))):
        raise Hold("CAB内の目標版がLVFSの更新候補と一致しません。")
    payload = read_cab_files(path, payload_name).get(payload_name)
    if not payload or len(payload) < 16:
        raise Hold("CAB内のペイロードを読み取れません。")
    scope = check_capsule_scope(payload, guid, profile)
    return (scope, payload, raw_version) if include_payload else scope


def marker_path():
    return LOCK_DIR / ("mknk-bios-update-" + str(uuid.UUID(BOOT_ID.read_text().strip())) + ".request")


def check_marker(path):
    if marker_exists(path):
        raise Hold("このLinux起動中に既に予約の準備または依頼が記録されています。--status で確認してください。")


def marker_exists(path):
    # 更新前のサンプルが同じ起動中に書き込んだ記録も参照する。
    for marker in (path, LEGACY_LOCK_DIR / path.name):
        try:
            marker.lstat()
        except FileNotFoundError:
            continue
        return True
    return False


def send_once(path, cabinet_fd, revalidate):
    check_marker(path)
    # /run直下のroot所有ディレクトリを原子的に確保する。利用者のログアウトでは消えない。
    try:
        sudo_command(["/usr/bin/mkdir", "-m", "0755", "--", str(path)], "同一起動での更新依頼の記録")
    except Hold:
        check_marker(path)
        raise
    try:
        device = revalidate()
        child = subprocess.Popen([FWUPDMGR, "--no-reboot-check", "local-install",
                                  cabinet_path(cabinet_fd), device["DeviceId"]], pass_fds=(cabinet_fd,))
    except (Error, Hold, OSError, ValueError, subprocess.CalledProcessError) as exc:
        # 検査で止まった場合と子プロセスを開始できなかった場合は、未送信なので記録を解除する。
        try:
            sudo_command(["/usr/bin/rmdir", "--", str(path)], "未送信の更新依頼記録の解除")
        except (Hold, OSError) as cleanup_error:
            raise Hold(f"{visible(exc)} 未送信の依頼記録を解除できません。--status で確認してください。") from cleanup_error
        raise
    try:
        code = child.wait()
    except KeyboardInterrupt:
        child.wait()
        raise
    if code:
        raise Error(f"fwupdの終了コードは{code}です。依頼後の状態は未確定です。"
                    " 予約が残っていると次回起動で適用され得ます。--status でEFIの予約を確認してください。"
                    " 同じ起動での再送は保留します。")
    return device


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


def show_efi_variables(guid):
    try:
        pending, _ = fwupd_efi_state()
        if pending:
            target = f"BIOS対象{pending.count(guid)}件" if guid else "BIOSへの帰属は確認不能"
            print(f"fwupd-efi  実行待ち登録{len(pending)}件（{target}）")
        else:
            print("fwupd-efi  実行待ち登録なし")
    except (Hold, OSError) as exc:
        print("fwupd-efi  確認不能", visible(exc))

    try:
        next_entry = boot_next()
        print("次回起動先 ", "指定なし" if next_entry is None else f"Boot{next_entry:04X}")
    except (Hold, OSError) as exc:
        print("次回起動先  確認不能", visible(exc))

    try:
        delivery = disk_delivery_requested()
        print("ディスク配送 ", "配送指示あり" if delivery else "標準の配送指示なし")
    except (Hold, OSError) as exc:
        print("ディスク配送  確認不能", visible(exc))


def show_reservations(guid):
    try:
        mounts = mount_points()
    except (OSError, ValueError) as exc:
        print("EFI予約とディスク配置先  確認不能", visible(exc))
        return
    try:
        require_efivarfs(mounts)
    except Hold as exc:
        print("EFI変数　確認不能", visible(exc))
    else:
        show_efi_variables(guid)

    try:
        esp, _ = find_esp(mounts)
    except (Error, Hold, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("ディスク配置先  確認不能", visible(exc))
        return
    for path, directory in DISK_DELIVERY_PATHS:
        try:
            present = esp_has_entry(esp, path, directory=directory)
        except (Hold, OSError) as exc:
            print("配送ファイル  確認不能", path, visible(exc))
        else:
            print("配送ファイル ", "配置先に項目あり（内容未確認）" if present else "配置先に項目なし", path)


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


def require_fwupdmgr():
    if not os.path.isfile(FWUPDMGR):
        raise Error("fwupdmgr が見つかりません。Ubuntu / Mintでは sudo apt install fwupd で導入できます。")


def show_status():
    inventory_error = None
    guid = device = None
    try:
        guid = read_esrt()
        require_fwupdmgr()
        _, device, _ = inventory(guid)
        describe(device)
    except (Error, Hold, OSError, ValueError, subprocess.CalledProcessError) as exc:
        inventory_error = exc
        print("実機BIOS  確認不能", visible(exc))
    show_reservations(guid)
    try:
        if marker_exists(marker_path()):
            print("この起動で更新依頼の記録があります。実機版、EFIの予約、履歴を併せて確認してください。")
    except (OSError, ValueError) as exc:
        print("この起動の依頼記録  確認不能", visible(exc))
    if inventory_error is not None:
        print("BIOSのfwupd履歴  対象を確認できません")
        raise inventory_error
    show_history(device, rows(["get-history"], allow_empty=True))


def main():
    parser = argparse.ArgumentParser(description="ネコシステム社 | システムBIOSの確認と更新予約",
                                     epilog="引数なしは --check。実際の適用後は --status で現在版を確認します。")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="LVFS安定版の更新候補を確認（既定）")
    modes.add_argument("--apply", action="store_true", help="内容を確認してBIOS更新を予約")
    modes.add_argument("--status", action="store_true", help="実機版、EFIの予約、履歴を表示。配布元への通信なし")
    parser.add_argument("--device-id", metavar="ID", help="--apply で照合するシステムBIOSのDevice ID")
    opt = parser.parse_args()
    if opt.device_id is not None and (not opt.apply or not re.fullmatch(r"[0-9a-fA-F]{40}", opt.device_id)):
        parser.error("--device-id は --apply と組み合わせ、40桁の16進数で指定してください。")
    if opt.status:
        show_status()
        return
    require_fwupdmgr()
    if opt.apply and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Hold("--apply はfwupdの確認に応答できる対話端末で実行してください。")
    if not ESRT.is_dir():
        raise Hold("UEFIのESRTを取得できません。この方法で更新できるBIOSを特定できません。")
    guid, device, devices = inventory()
    if opt.device_id is not None and opt.device_id.lower() != device["DeviceId"]:
        raise Hold("指定したDevice IDが実機のシステムBIOSと一致しません。")
    try:
        settings = read_settings()
        remote = stable_remote(settings)
        if opt.apply:
            marker = marker_path()
            check_marker(marker)
            esp, esp_guid, secure_boot, bootloader_capability = check_ready(
                device, devices, rows(["get-history"], allow_empty=True), settings)
        catalog, daemon_version = load_stable_catalog(remote, settings, guid, device)
        # メタデータを更新すると、fwupdが同じBIOSの表示版・版形式を更新することがある。
        new_guid, refreshed, peers = inventory()
        if (new_guid != guid or refreshed["DeviceId"] != device["DeviceId"]
                or set(strings(refreshed, "Guid")) != set(strings(device, "Guid"))):
            raise Hold("カタログの照会中に機器の識別情報が変化しました。再確認してください。")
    except (Error, Hold, OSError, ValueError, subprocess.CalledProcessError):
        describe(device)
        raise
    device, devices = refreshed, peers
    describe(device)
    release = candidate(device)
    active_remote = stable_remote(settings)
    compare_remote(remote, active_remote)
    result = require_catalog_release(catalog, device, devices, guid, release, active_remote,
                                     daemon_version=daemon_version)
    if not release:
        if device.get("UpdateError"):
            print("fwupd    ", visible(device["UpdateError"]))
        if result.unavailable:
            message = result.unavailable
        elif result.model_listed:
            message = ("照合したLVFS安定版に、この機種は掲載されています。"
                       " このBIOSで利用できる新版はありません（現行ブランチ）。")
        else:
            message = "照合したLVFS安定版で、この機種の掲載を確認できませんでした。"
        message += " メーカーサイトを含めた最新版かどうかは未確認です。"
        if opt.apply:
            raise Hold(message)
        print(message)
        return
    print("更新候補  ", visible(device["Version"]), "→", visible(release["Version"]), "（lvfs 安定版）")
    if not opt.apply:
        print("予約する場合は --apply を付けて実行してください。")
        return
    profile = support_profile(settings, guid, device)
    index_hashes = release_hashes(release)
    approved_hashes = index_hashes | result.hashes
    with open_cabinet() as cabinet:
        print("配布ファイルを取得し、署名・ハッシュ・対象を照合します。", flush=True)
        cab = fetch_cab(release, remote, cabinet, settings, download_size=result.download_size)
        verify_cabinet_hashes(cabinet, {key: value for key, value in result.hashes.items() if key not in index_hashes})
        scope = verify_cab(cab, release, guid, device, devices, profile)
        print("対象     ", visible(release["AppstreamId"]))
        print("適用範囲  ", scope)
        print("CAB      ", " ".join(f"{algorithm} {digest}" for algorithm, digest in approved_hashes.items()))
        print("AC電源を維持してください。他のツールで起動待ちの更新を予約済みなら、ここで終了してください。")
        print("予約後は次の通常起動で適用され得ます。再起動のタイミングは利用者が選びます。")
        try:
            consent = input("このBIOS更新を予約しますか [y/N] ").strip().casefold()
        except EOFError:
            consent = ""
        if consent not in ("y", "yes"):
            print("取り消しました。")
            return

        def revalidate():
            # 依頼記録のsudo認証を済ませてから、送信に使う情報を取り直す。
            active_settings = read_settings()
            if active_settings != settings:
                raise Hold("承認後に安定版配布元または機種別対応情報が変更されました。再確認してください。")
            active_remote = stable_remote(active_settings)
            compare_remote(remote, active_remote)
            catalog, daemon_version = load_stable_catalog(active_remote, active_settings, guid, device)
            new_guid, current, peers = inventory()
            identity_fields = ("DeviceId", "Version", "VersionFormat", "Branch", "CompositeId")
            if (new_guid != guid or any(current.get(k) != device.get(k) for k in identity_fields)
                    or set(strings(current, "Guid")) != set(strings(device, "Guid"))):
                raise Hold("承認後に機器情報が変化しました。再確認してください。")
            updated = candidate(current)
            if (not updated or any(updated.get(k) != release.get(k) for k in ("Version", "AppstreamId", "RemoteId"))
                    or not same_cab(approved_hashes, release_hashes(updated))):
                raise Hold("承認後に配布候補が変わりました。再確認してください。")
            active_profile = support_profile(active_settings, guid, current)
            verify_cab(cab, updated, guid, current, peers, active_profile)
            active_esp, active_esp_guid, active_secure_boot, active_bootloader_capability = check_ready(
                current, peers, rows(["get-history"], allow_empty=True), active_profile)
            if (active_esp, active_esp_guid) != (esp, esp_guid):
                raise Hold("承認後に配送区画が変わりました。再確認してください。")
            if active_secure_boot != secure_boot:
                raise Hold("承認後にSecure Bootの有効状態が変わりました。再確認してください。")
            if active_bootloader_capability != bootloader_capability:
                raise Hold("承認後にブートローダーの更新対応通知が変わりました。再確認してください。")
            if read_settings() != active_settings:
                raise Hold("送信準備中に設定が変更されました。再確認してください。")
            active_remote = stable_remote(active_settings)
            compare_remote(remote, active_remote)
            fresh = require_catalog_release(catalog, current, peers, guid, updated, active_remote,
                                            daemon_version=daemon_version, verified_hashes=approved_hashes.values())
            fresh_hashes = release_hashes(updated) | fresh.hashes
            if not same_cab(approved_hashes, fresh_hashes):
                raise Hold("承認後に配布候補のCABハッシュが変わりました。再確認してください。")
            verify_cabinet_hashes(cabinet, {key: value for key, value in fresh_hashes.items() if key not in approved_hashes})
            if fresh.download_size is not None and os.fstat(cabinet.fileno()).st_size != fresh.download_size:
                raise Hold("承認後に署名済みカタログのCAB受信サイズが変わりました。")
            return current

        current = send_once(marker, cabinet.fileno(), revalidate)
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
    print("実機版、EFIの予約、履歴は --status で確認できます。")


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
