"""Read-only Linux firmware observation and final physical delivery checks.

The service owns host pseudonymization, request attribution and serialization.
The payload hash and length are inputs from the unprivileged CAB verifier.
"""

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from firmware_api import fw

Hold = fw.Hold
READ_ERRORS = (Hold, fw.Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError)
UNKNOWN = "確認できません"
SHA256 = re.compile(r"[0-9a-f]{64}")
UX_GUID = "3b8c8162-188c-46a4-aec9-be43f1d65697"
# The supported fwupd Linux uefi_capsule backend obtains its device from ESRT.
# ESRT supplies no FMP hardware instance, so its EFI update records use zero.
ESRT_REGISTRATION_INSTANCE = 0


def target_version_matches(plan, obs):
    fmt = obs["version_format"]
    if not fmt or plan.get("version_format") != fmt:
        return False
    try:
        return fw.version_key(obs["current"], fmt) == fw.version_key(plan.get("target"), fmt)
    except (Hold, ValueError):
        return False


def target_installed(plan, obs):
    raw = plan.get("target_raw")
    return (type(raw) is not int or obs.get("fw_version") == raw) and target_version_matches(plan, obs)


def _uuid(path):
    try:
        value = uuid.UUID(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return ""
    # Empty, erased and common SMBIOS example values are not host identities.
    if value.int in (0, 2**128 - 1) or value.hex in {
        "00020003000400050006000700080009", "03000200040005000006000700080009",
        "00112233445566778899aabbccddeeff", "0123456789abcdef0123456789abcdef",
    }:
        return ""
    return str(value)


def _display_dmi():
    fields = {}
    for name in (*fw.MODEL_FIELDS, "bios_version"):
        try:
            fields[name] = (fw.DMI / name).read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            fields[name] = ""
        except (OSError, UnicodeError):
            fields[name] = None
    generic = {"system product name", "default string", "to be filled by o.e.m.", "not applicable"}
    product = fields["product_name"]
    if not product or product.lower() in generic:
        names = [fields["board_name"], fields["board_version"]]
    else:
        names = [fields["sys_vendor"], product, fields["product_sku"]]
    model = " / ".join(dict.fromkeys(fw.visible(n)[:160] for n in names if n and n.lower() not in generic))
    return fields, model or UNKNOWN


def _esrt_resource():
    # Never convert unreadable last-attempt attributes to zero (initial/success).
    matches = []
    for entry in sorted(fw.ESRT.iterdir()):
        if re.fullmatch(r"entry[0-9]+", entry.name):
            if int((entry / "fw_type").read_text(encoding="ascii").strip(), 0) == 1:
                matches.append(entry)
    if len(matches) != 1:
        raise Hold(f"ESRTのシステムBIOS資源は{len(matches)}件です。")
    entry = matches[0]
    guid = str(uuid.UUID((entry / "fw_class").read_text(encoding="ascii").strip()))
    values = []
    for name in ("fw_version", "last_attempt_version", "last_attempt_status", "capsule_flags"):
        try:
            value = int((entry / name).read_text(encoding="ascii").strip(), 0)
            values.append(value if 0 <= value <= 0xffffffff else None)
        except (OSError, ValueError):
            values.append(None)
    return guid, *values


def _daemon_busy():
    # A pending history row and the live daemon's write/authentication activity
    # are distinct. An unavailable daemon is never evidence that it is idle.
    Fwupd, GLib = fw.fwupd_bindings()
    from gi.repository import Gio
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        reply = bus.call_sync(fw.FWUPD_ID, "/", "org.freedesktop.DBus.Properties", "Get",
                              GLib.Variant("(ss)", (fw.FWUPD_ID, "Status")),
                              GLib.VariantType.new("(v)"), Gio.DBusCallFlags.NONE, 5000, None)
        status = reply.unpack()[0]
    except GLib.Error as exc:
        raise Hold("fwupdの処理状態を取得できません。") from exc
    if status == Fwupd.Status.UNKNOWN:
        raise Hold("fwupdの処理状態を確認できません。")
    return status != Fwupd.Status.IDLE


def _local_rows(method):
    # Avoid starting fwupdmgr subprocesses during desktop QueryEndSession.
    Fwupd, GLib = fw.fwupd_bindings()
    client = Fwupd.Client.new()
    try:
        items = getattr(client, method)(None)
        return [json.loads(item.to_json_string(Fwupd.CodecFlags.NONE)) for item in items]
    except GLib.Error as exc:
        if method == "get_history" and exc.domain == "FwupdError" and exc.code == Fwupd.Error.NOTHING_TO_DO:
            return []
        raise Hold("fwupdから機器・履歴を読み取れません。") from exc


def _history_text(device_id, history):
    lines = []
    for row in sorted((r for r in history if r.get("DeviceId") == device_id),
                      key=lambda r: int(r.get("Modified", 0)), reverse=True)[:20]:
        versions = [fw.visible(r["Version"]) for r in row.get("Releases", [])
                    if isinstance(r, dict) and r.get("Version")]
        stamp = ""
        if type(row.get("Modified")) is int and 0 < row["Modified"] < 253402300800:
            stamp = datetime.fromtimestamp(row["Modified"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines.append("  ".join(filter(None, [stamp, "目標 " + ("・".join(versions) or "不明"),
                                            fw.STATES.get(row.get("UpdateState"), "結果未確定"),
                                            fw.visible(row.get("UpdateError", ""))[:240]])))
    return "\n".join(lines) or "このBIOSのfwupd履歴はありません。"


def _fw_pending(devices, history):
    attached = {d["DeviceId"] for d in devices}
    waiting = set()
    busy = False
    for row in [*devices, *history]:
        if row.get("DeviceId") not in attached:
            continue
        problems = fw.strings(row, "Problems")
        if row.get("UpdateState") in (1, 4) or "update-pending" in problems:
            waiting.add(row["DeviceId"])
        if "update-in-progress" in problems:
            busy = True
    return waiting, busy


def _power(profile, device):
    fw.check_power()
    rule = profile.get("power", {})
    if not isinstance(rule, dict):
        raise Hold("機種別の給電条件を確認できません。")
    minimum = rule.get("minimum_battery_percent", device.get("BatteryThreshold"))
    levels, online = [], []
    for supply in fw.POWER.iterdir():
        if fw.power_field(supply, "scope") == "Device":
            continue
        kind = fw.power_field(supply, "type")
        if not kind:
            raise Hold("電源装置の種類を確認できません。")
        if kind == "Battery":
            present = fw.power_field(supply, "present")
            if present == "0":
                continue
            if present not in ("", "1"):
                raise Hold("バッテリーの装着状態を確認できません。")
            if fw.power_field(supply, "status") == "Discharging":
                raise Hold("バッテリーが放電中です。ACアダプターを確認してください。")
            level = fw.power_field(supply, "capacity")
            if not level.isdecimal() or int(level) > 100:
                raise Hold("システムバッテリーの残量を確認できません。")
            levels.append(int(level))
        else:
            value = fw.power_field(supply, "online")
            if value not in ("", "0", "1", "2"):
                raise Hold("外部給電の状態を確認できません。")
            if value:
                online.append(value in ("1", "2"))
    if levels:
        if rule.get("batteryless") is True:
            raise Hold("バッテリーの搭載状況が機種別の条件と異なります。")
        if not any(online):
            raise Hold("ACアダプターを接続してください。")
        if type(minimum) is not int or not 0 <= minimum <= 100:
            raise Hold("この機種の必要な最低充電量を確認できません。")
        if min(levels) < minimum:
            raise Hold(f"バッテリーを{minimum}%以上まで充電してください。")
    elif rule.get("batteryless") is not True or (online and not any(online)):
        raise Hold("バッテリー非搭載と常時給電を機種別の条件で確認できません。")
    problems = set(fw.strings(device, "Problems")) - {"update-pending"}
    if problems:
        raise Hold("BIOSの更新条件を満たしていません。 " + "、".join(sorted(problems)))


def _physical_disk(device_number):
    partition = fw.partition_sysfs_path(device_number)
    disk = partition.parent
    # Bind the disk as well as the GPT identifier. A replacement disk may
    # acquire the very same Linux major/minor, slot and cloned partition UUID.
    for key in ("wwid", "device/wwid", "device/cid", "device/serial", "serial"):
        try:
            value = (disk / key).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            continue
        if value and value.lower() not in ("unknown", "none") and value.strip("0"):
            return hashlib.sha256((key + "\0" + value).encode("ascii")).hexdigest()
    raise Hold("EFIシステム区画の物理媒体の識別情報を確認できません。")


def _route(esp, partuuid, mount, guid, profile, secure, capability, geometry, disk_boot):
    boot = profile.get("secure_boot", {})
    delivery = boot.get("delivery", "nvram")
    name = f"fwupd-{guid}.cap"
    partition, start_lba, size_lba = geometry
    route = dict(esp=str(esp), partuuid=partuuid, device_number=mount.device, disk=_physical_disk(mount.device),
                 partition=partition, start_lba=start_lba, size_lba=size_lba, secure_boot=secure,
                 delivery=delivery, capability=list(capability) if capability else None)
    if delivery == "capsule-on-disk":
        route["file"] = f"{fw.STANDARD_CAPSULE_DIR}/{name}"
        # Bind the verified first active BootOrder entry (including arguments).
        if disk_boot is None:
            raise Hold("有効な通常起動項目を確認できません。")
        route["boot_entry"] = list(disk_boot)
    elif delivery in ("nvram", "shim"):
        vendor = boot.get("esp_vendor_dir", "")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", vendor):
            raise Hold("機種別のESP上の更新ローダーの配置先を確認できません。")
        route["file"] = f"EFI/{vendor}/fw/{name}"
        route["loader"] = f"EFI/{vendor}/fwupdx64.efi"
        package = Path(boot.get("efi_app_dir", str(fw.EFI_APP_DIR)))
        loader = None if secure else fw.efi_asset_sha256(package / "fwupdx64.efi", check_application=True)
        loader = loader or fw.efi_asset_sha256(package / "fwupdx64.efi.signed", check_application=True)
        if not loader:
            raise Hold("配送に必要なfwupd EFIローダーを確認できません。")
        route["loader_sha256"] = loader
        if secure:
            route["shim"] = f"EFI/{vendor}/shimx64.efi"
            route["shim_sha256"] = (fw.efi_asset_sha256(package / "shimx64.efi.signed")
                                    or fw.efi_asset_sha256(esp / route["shim"]))
    else:
        raise Hold("この配送方式を確認できません。")
    if "ux_capsule_sha256" in boot:
        vendor = boot.get("esp_vendor_dir", "")
        ux_hash = boot["ux_capsule_sha256"]
        if (not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", vendor)
                or not isinstance(ux_hash, str) or not SHA256.fullmatch(ux_hash)):
            raise Hold("表示用カプセルの機種別の配置・ハッシュを確認できません。")
        route.update(ux_file=f"EFI/{vendor}/fw/fwupd-{UX_GUID}.cap", ux_hash=ux_hash)
        if delivery == "capsule-on-disk":
            if boot.get("normal_boot_entry_sha256") != route["boot_entry"][1]:
                raise Hold("表示登録が実行されない通常の起動経路を確認できません。")
    return route


def _relative_file(path, route):
    """Accept only a single GPT HD() + File() on the checked physical ESP."""
    expected = fw.BootPartition(route["partuuid"], route["partition"], route["start_lba"], route["size_lba"], True)
    if fw.boot_disk_partition(path) != expected:
        raise Hold("EFIデバイスパスの物理区画を承認したESPに照合できません。")
    name = fw.short_efi_file(path)
    if name is None:
        raise Hold("EFIデバイスパスのファイル名を確認できません。")
    return name


def _nvram_files(esp, plan, route, next_boot):
    if next_boot is None:
        raise Hold("fwupdのEFIローダーへの次回起動先がありません。")
    boot = fw.read_efi_variable(fw.EFIVARS / f"Boot{next_boot:04X}-{fw.EFI_GLOBAL}")
    label, path = fw.boot_load_option(boot)
    if (label not in ("Linux Firmware Updater", "Linux-Firmware-Updater")
            or (int.from_bytes(boot[4:8], "little") & 0x1f01) != 1):
        raise Hold("次回起動先は有効な更新用ローダーではありません。")
    name = _relative_file(path, route)
    option_start = 12 + len(label.encode("utf-16-le")) + len(path)
    options = boot[option_start:]
    if route["secure_boot"]:
        # fwupd writes the shim argument as a UTF-16LE EFI path with one leading backslash.
        loader_option = options.decode("utf-16-le").lower()
        if name != route["shim"].casefold() or loader_option not in ("\\fwupdx64.efi\0", "fwupdx64.efi\0"):
            raise Hold("次回起動のshimとローダー引数を確認できません。")
        if fw.efi_asset_sha256(esp / route["shim"]) != route["shim_sha256"]:
            raise Hold("配置済みshimの内容が一致しません。")
    elif name != route["loader"].casefold() or options:
        raise Hold("次回の更新用ローダーのパスと引数が一致しません。")
    if fw.efi_asset_sha256(esp / route["loader"]) != route["loader_sha256"]:
        raise Hold("配置済みの更新用ローダーの内容が一致しません。")
    guid, instance = plan["guid"], route["registration_instance"]
    _pending_file(f"fwupd-{guid}-{instance}", guid, instance, route, route["file"],
                  capsule_flags=route["capsule_flags"])


def _pending_file(name, guid, instance, route, expected_file, *, capsule_flags=None):
    data = fw.read_efi_variable(fw.EFIVARS / f"{name}-{fw.FWUPDATE_GUID}")
    if (len(data) < 56 or int.from_bytes(data[:4], "little") & 7 != 7
            or int.from_bytes(data[4:8], "little") != 7
            or str(uuid.UUID(bytes_le=data[8:24])) != guid
            or (capsule_flags is not None and int.from_bytes(data[24:28], "little") != capsule_flags)
            or int.from_bytes(data[28:36], "little") != instance
            or int.from_bytes(data[52:56], "little") != 1
            or _relative_file(data[56:], route) != expected_file.casefold()):
        raise Hold("fwupd-efiの実行待ち登録と承認したファイルが一致しません。")


def _ux_file(esp, route):
    """Only a model/build-verified, byte-identical boot-screen asset is auxiliary."""
    if not route.get("ux_hash"):
        raise Hold("表示用カプセルを機種別の配布資材に照合できません。")
    # fwupd-efi uses the display header's own flags, verified with the asset below.
    _pending_file("fwupd-ux-capsule", UX_GUID, ESRT_REGISTRATION_INSTANCE, route, route["ux_file"])
    with (esp / route["ux_file"]).open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 98 <= size <= 32 * 1024 * 1024:
            raise Hold("表示用カプセルの大きさを確認できません。")
        data = stream.read(size + 1)
    if (hashlib.sha256(data).hexdigest() != route["ux_hash"] or len(data) != size
            or data[:16] != uuid.UUID(UX_GUID).bytes_le
            or struct.unpack_from("<III", data, 16) != (28, 0x10000, size)
            or data[28] != 1 or any(data[30:36]) or sum(data) % 256):
        raise Hold("表示用カプセルの内容・ヘッダー・チェックサムを確認できません。")
    bmp = memoryview(data)[44:]
    file_size, reserved, pixels, header, width, height, planes, bpp, compression = struct.unpack_from(
        "<IIIIiiHHI", bmp, 2)
    if (bmp[:2] != b"BM" or file_size != len(bmp) or reserved or header < 40 or header + 14 > pixels
            or not (width > 0 and height > 0 and planes == 1 and bpp in (1, 4, 8, 16, 24, 32))
            or compression or pixels + ((width * bpp + 31) // 32) * 4 * height > len(bmp)):
        raise Hold("表示用カプセルに含まれるビットマップの形式・範囲を確認できません。")


def _matches_file(esp, plan, route):
    path = esp / route["file"]
    length = plan.get("payload_size")
    digest = plan.get("payload_sha256")
    if type(length) is not int or length <= 0 or not SHA256.fullmatch(digest or ""):
        raise Hold("承認済みの配置後カプセルの長さ・ハッシュを確認できません。")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size != length
                or hashlib.file_digest(stream, "sha256").hexdigest() != digest):
            raise Hold("ESPのカプセルの内容が承認した配布物と一致しません。")


def _bound_route(esp, partuuid, mounts, plan, profile, capability, capsule_flags):
    mount = mounts[str(esp)]
    geometry = fw.partition_geometry(mount.device)
    secure, disk_boot = fw.check_boot_delivery(esp, partuuid, mount.device, profile,
                                               bootloader_capability=capability, geometry=geometry)
    route = _route(esp, partuuid, mount, plan["guid"], profile, secure, capability, geometry, disk_boot)
    route["power_action"] = "shutdown" if plan.get("shutdown") else "reboot"
    route["power_rule"] = profile.get("power", {})
    if route["delivery"] != "capsule-on-disk":
        if capsule_flags is None:
            raise Hold("ESRTのカプセルフラグを確認できません。")
        # fwupd 2.0.20 on x86_64 adds both reset flags only when neither was set in ESRT.
        reset_flags = 0x10000 | 0x40000  # PERSIST_ACROSS_RESET | INITIATE_RESET
        route["capsule_flags"] = capsule_flags if capsule_flags & reset_flags else capsule_flags | reset_flags
        fmp = profile.get("fmp", {})
        instance = fmp.get("hardware_instance", 0) if isinstance(fmp, dict) else None
        if type(instance) is not int or not 0 <= instance < 2**64:
            raise Hold("BIOS資源のハードウェアインスタンスを確認できません。")
        route.update(fmp_instance=instance, registration_instance=ESRT_REGISTRATION_INSTANCE)
    return route


def _esp_reservation(plan, obs, waiting, device, profile, facts):
    esp, partuuid, mounts, pending, capability, next_boot, cod, standard, dell = facts
    evidence = []
    if pending:
        evidence.append(f"fwupd-efi 実行待ち{len(pending)}件（BIOS対象{pending.count(obs['guid'])}件）")
    if next_boot is not None:
        evidence.append(f"次回起動先 Boot{next_boot:04X}")
    if cod:
        evidence.append("ディスク配送指示あり")
    if standard or dell:
        evidence.append("ESPに配置済みの更新ファイルあり")
    if waiting:
        evidence.append("fwupdに起動待ちの記録あり")
    binding = plan.get("binding", {}) if plan else {}
    if not binding:
        return ("foreign", "。".join(evidence)) if evidence else ("clear", "")
    mount = mounts[str(esp)]
    partition, start_lba, size_lba = fw.partition_geometry(mount.device)
    if ((binding.get("partuuid"), binding.get("esp"), binding.get("disk"), binding.get("partition"))
            != (partuuid, str(esp), _physical_disk(mount.device), partition)):
        raise Hold("現在の配送区画が承認した区画と異なります。")
    if "start_lba" not in binding and "size_lba" not in binding:
        # Legacy plans omitted geometry. Any active route must still verify its live EFI paths.
        binding = dict(binding, start_lba=start_lba, size_lba=size_lba)
    if (binding.get("start_lba"), binding.get("size_lba")) != (start_lba, size_lba):
        raise Hold("現在の配送区画の位置・長さが承認した区画と異なります。")
    if not evidence:
        return "clear", ""
    if (obs["guid"] != plan.get("guid") or device.get("DeviceId") != plan.get("device")
            or not profile or dell or waiting - {plan.get("device")}):
        return "foreign", "。".join(evidence)
    route = _bound_route(esp, partuuid, mounts, plan, profile, capability, obs["capsule_flags"])
    if "instance" in binding and "fmp_instance" not in binding and "registration_instance" not in binding:
        binding = dict(binding, registration_instance=ESRT_REGISTRATION_INSTANCE)
        binding["fmp_instance"] = binding.pop("instance")
    if "capsule_flags" in route and "capsule_flags" not in binding:
        # Older pending plans bound the loader and all other route fields. The
        # actual registration must still match this device's live ESRT flags.
        binding = dict(binding, capsule_flags=route["capsule_flags"])
    if obs["boot"] and plan.get("boot") and obs["boot"] != plan["boot"] and "device_number" in binding:
        # The disk, GPT geometry and verified boot entry stay bound across Linux boots.
        binding = dict(binding, device_number=mount.device)
    if route != binding:
        raise Hold("物理区画・起動先・配送方式が承認した内容と一致しません。")
    display = pending.count(UX_GUID) == 1
    if display:
        # Preflight excluded every pending entry. Validate this optional addition
        # against the approved display asset and boot route before excluding it.
        _ux_file(esp, route)
        pending = [guid for guid in pending if guid != UX_GUID]
    if route["delivery"] == "capsule-on-disk":
        if next_boot is not None or pending:
            return "foreign", "。".join(evidence)
        if standard:
            files = list((esp / fw.STANDARD_CAPSULE_DIR).iterdir())
            if len(files) != 1 or files[0].name.casefold() != Path(route["file"]).name.casefold():
                raise Hold("ESPに承認したカプセル以外の項目があります。")
            _matches_file(esp, plan, route)
        if (not cod and not waiting and obs["boot"] and plan.get("boot") and obs["boot"] != plan["boot"]
                and obs["can_identify"] and target_installed(plan, obs) and obs["running"] is False
                and obs["attempt_comparable"] and not obs["new_failure"]):
            residue = "と".join(name for present, name in ((standard, "カプセルファイル"), (display, "表示用登録"))
                               if present)
            obs["prepare_block"] = f"前回の更新の{residue}が残っているため、新しい更新の準備を保留します。"
            return "clear", f"配送指示は解除され、照合済みの{residue}が残っています。"
        if not standard:
            raise Hold("配送指示または待機記録がありますが、対象のカプセルを確認できません。")
        if not cod:
            raise Hold("カプセルは配置済みですが、ディスク配送指示がありません。")
    else:
        if cod or standard or pending != [plan["guid"]]:
            return "foreign", "。".join(evidence)
        _nvram_files(esp, plan, route, next_boot)
        _matches_file(esp, plan, route)
    return "matching", "承認したBIOSカプセルと起動先を実機で確認しました。"


def _reservation(plan, obs, device, profile, waiting):
    mounts = fw.mount_points()
    errors = []

    def read(label, call, *args, **kwargs):
        try:
            return call(*args, **kwargs)
        except READ_ERRORS as exc:
            errors.append(label + " " + fw.visible(exc))
            return None

    # Preserve independent EFI/ESP observations when one interface is unreadable.
    read("EFI変数", fw.require_efivarfs, mounts)
    nvram = next_boot = cod = None
    if not errors:
        nvram = read("fwupd-efi", fw.fwupd_efi_state)
        next_boot = read("次回起動先", fw.boot_next)
        cod = read("ディスク配送指示", fw.disk_delivery_requested)
    volume = read("EFIシステム区画", fw.find_esp, mounts)
    standard = dell = None
    if volume is not None:
        esp, partuuid = volume
        standard = read(fw.STANDARD_CAPSULE_DIR, fw.esp_has_entry, esp, fw.STANDARD_CAPSULE_DIR, directory=True)
        dell = read(fw.DELL_RECOVERY_FILE, fw.esp_has_entry, esp, fw.DELL_RECOVERY_FILE, directory=False)
    if errors:
        if nvram and nvram[0]:
            errors.append(f"読取済みのfwupd-efi登録 {len(nvram[0])}件（BIOS対象{nvram[0].count(obs['guid'])}件）")
        if standard or dell or cod or next_boot is not None:
            errors.append("EFIに既存の配送ファイルまたは起動指示があります。")
        raise Hold("。".join(errors))
    return _esp_reservation(plan, obs, waiting, device, profile,
                            (esp, partuuid, mounts, *nvram, next_boot, cod, standard, dell))


def _attempt(plan, obs):
    if not plan or obs["guid"] != plan.get("guid"):
        return False, False
    version, status = obs["attempt_version"], obs["attempt_status"]
    if None in (version, status):
        return False, False
    previous = (plan.get("attempt_version"), plan.get("attempt_status"))
    if status == 0 or (version, status) == previous:
        return True, False
    raw = plan.get("target_raw")
    # A failed ESRT attempt may have no recorded version. Zero cannot identify a different release.
    if version == 0 or type(raw) is not int:
        return False, False
    if version != raw:
        return True, False
    # UEFI 2.11 standard failure codes 1..8. Vendor/reserved codes require
    # model-specific interpretation, and cannot establish success.
    if None in previous or status not in range(1, 9):
        return False, False
    return True, True


def _owns_marker(marker, plan, boot):
    if not plan or plan.get("boot") != boot or not fw.GUID_TEXT.fullmatch(plan.get("id") or ""):
        return False
    try:
        directory = os.open(marker, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
            fd = os.open("gui-operation", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                        or info.st_nlink != 1):
                    return False
                saved = os.read(fd, 38)
            finally:
                os.close(fd)
        finally:
            os.close(directory)
        operation = plan["id"].encode("ascii")
        if saved not in (operation, operation + b"\n"):
            return False
        # A legacy CLI request may coexist with our new marker during upgrade.
        try:
            (fw.LEGACY_LOCK_DIR / marker.name).lstat()
        except FileNotFoundError:
            return True
    except OSError:
        pass
    return False


def observe(plan=None):
    fields, model = _display_dmi()
    obs = dict(model=model, current=fw.visible(fields["bios_version"] or UNKNOWN)[:160], guid="", device="",
               version_format="", boot=_uuid(fw.BOOT_ID), machine="", can_identify=False,
               reservation="unknown", detail="", history="", fw_version=None, capsule_flags=None, prepare_block="",
               attempt_version=None, attempt_status=None, attempt_comparable=False,
               new_failure=False, running=None, power="", support_url="", recovery_url="")
    reasons = []
    try:
        (obs["guid"], obs["fw_version"], obs["attempt_version"], obs["attempt_status"],
         obs["capsule_flags"]) = _esrt_resource()
    except READ_ERRORS as exc:
        reasons.append("実機のESRTを確認できません。 " + fw.visible(exc))
    device, profile, waiting = {}, {}, set()
    try:
        profile = fw.read_settings()
        dmi = {k: fields[k] for k in fw.MODEL_FIELDS}
        if (dmi["sys_vendor"] and dmi["product_name"] and None not in dmi.values() and profile.get("dmi") == dmi
                and (not obs["guid"] or profile.get("esrt_guid") == obs["guid"])):
            if obs["guid"] and profile.get("system_uuid_unique") is True:
                obs["machine"] = _uuid(fw.DMI / "product_uuid")
            for field in ("support_url", "recovery_url"):
                url = profile.get(field)
                if url:
                    try:
                        host, _, _ = fw.https_origin_path(url)
                    except (Hold, ValueError):
                        continue
                    if "%" not in host:
                        obs[field] = url
    except READ_ERRORS as exc:
        reasons.append(fw.visible(exc))
    if obs["guid"]:
        try:
            _, device, devices = fw.inventory(obs["guid"], devices=_local_rows("get_devices"))
            obs.update(device=device["DeviceId"], current=fw.visible(device["Version"]),
                       version_format=device.get("VersionFormat", ""), can_identify=True)
            raw = obs["fw_version"]
            target_raw = plan.get("target_raw") if plan else None
            if (raw is None or (device.get("VersionRaw") is not None and device["VersionRaw"] != raw)
                    or (type(target_raw) is int and target_version_matches(plan, obs) and raw != target_raw)):
                obs["can_identify"] = False
                reasons.append("ESRTで読み取った現在版とfwupdの実機版を照合できません。")
            history = _local_rows("get_history")
            obs["history"] = _history_text(obs["device"], history)
            waiting, busy = _fw_pending(devices, history)
            obs["running"] = _daemon_busy() or busy
            if obs["running"]:
                reasons.append("fwupdが処理中です。")
        except READ_ERRORS as exc:
            reasons.append("fwupdの機器・履歴・進行状態を確認できません。 " + fw.visible(exc))
    obs["attempt_comparable"], obs["new_failure"] = _attempt(plan, obs)
    if obs["new_failure"]:
        reasons.append(f"ESRTに目標版への新しい試行失敗があります（状態 {obs['attempt_status']}）。")
    try:
        reservation, detail = _reservation(plan, obs, device, profile, waiting)
        obs["reservation"] = "unknown" if reservation == "clear" and obs["running"] is None else reservation
        if detail:
            reasons.append(detail)
        if obs["boot"]:
            try:
                marker = fw.marker_path()
                cli_request = fw.marker_exists(marker) and not _owns_marker(marker, plan, obs["boot"])
            except READ_ERRORS:
                obs["reservation"] = "unknown"
                raise
            if cli_request:
                obs["reservation"] = "foreign"
                reasons.append("このLinux起動中にCLIから更新の依頼が記録されています。")
        if (obs["reservation"] == "matching" and obs["can_identify"]
                and obs["running"] is False and not obs["new_failure"]):
            if obs["boot"] != plan.get("boot") and not obs["attempt_comparable"]:
                raise Hold("起動後の試行結果を承認済みの更新に照合できません。")
            if obs["current"] != plan.get("current") or obs["version_format"] != plan.get("version_format"):
                raise Hold("予約後に現在版または版形式が変わりました。")
            if type(plan.get("shutdown")) is not bool or (
                    "needs-shutdown" in fw.strings(device, "Flags") and not plan["shutdown"]):
                raise Hold("必要な起動操作が承認した内容と異なります。")
            fw.support_profile(profile, obs["guid"], device)
            _power(profile, device)
            obs["power"] = "shutdown" if plan["shutdown"] else "reboot"
    except READ_ERRORS as exc:
        reasons.append(fw.visible(exc))
    obs["detail"] = "\n".join(reasons)
    return obs


def _platform():
    if platform.machine().lower() != "x86_64" or platform.system() != "Linux":
        raise Hold("対応する実行環境はx86_64のUEFI Linuxです。")
    release = platform.freedesktop_os_release()
    os_id, version = release.get("ID"), release.get("VERSION_ID", "")
    if not (os_id == "ubuntu" and version == "24.04"
            or os_id == "linuxmint" and version.split(".")[0] == "22"):
        raise Hold("対応OSはUbuntu 24.04 LTSまたはLinux Mint 22系です。")
    if fw.EFI_PLATFORM_SIZE.read_text(encoding="ascii").strip() != "64":
        raise Hold("64ビットUEFIを確認できません。")


def _encrypted_volumes(objects, root_device):
    """Classify only system media; never request encrypted-volume secrets."""
    kinds = set()
    root_seen = False
    indeterminate = False
    for interfaces in objects.values():
        block = interfaces.get(fw.UDISKS + ".Block")
        if not block or fw.UDISKS + ".Loop" in interfaces:
            continue
        number = block.get("DeviceNumber")
        # DeviceNumber is a Linux dev_t, encoded as a uint64 by UDisks.
        fs = interfaces.get(fw.UDISKS + ".Filesystem", {})
        root = number == root_device or any(bytes(p).rstrip(b"\0") == b"/" for p in fs.get("MountPoints", ()))
        root_seen |= root
        drive = objects.get(block.get("Drive"), {}).get(fw.UDISKS + ".Drive", {})
        if not root and drive.get("MediaAvailable") is False:
            continue
        if not root and block.get("HintSystem") is not True and drive.get("Removable") is not False:
            if "HintSystem" not in block and not drive:
                indeterminate = True
            continue
        if fw.UDISKS + ".PartitionTable" in interfaces:
            continue
        kind = block.get("IdType", "").lower()
        backing = block.get("CryptoBackingDevice", "/")
        if backing != "/":
            backing_type = objects.get(backing, {}).get(fw.UDISKS + ".Block", {}).get("IdType", "").lower()
            if "luks" in backing_type:
                kinds.add("luks")
            elif "bitlocker" in backing_type:
                kinds.add("bitlocker")
            else:
                kinds.add("other")
        if "luks" in kind:
            kinds.add("luks")
        elif "bitlocker" in kind:
            kinds.add("bitlocker")
        elif block.get("IdUsage") == "crypto" or fw.UDISKS + ".Encrypted" in interfaces:
            kinds.add("other")
        elif not kind:
            # These two GPT partitions have no filesystem by design.
            partition = interfaces.get(fw.UDISKS + ".Partition", {})
            if partition.get("Type", "").lower() not in {
                "e3c9e316-0b5c-4db8-817d-f92df00215ae", "21686148-6449-6e6f-744e-656564454649"
            }:
                indeterminate = True
        elif kind not in {"ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "ntfs",
                          "swap", "lvm2_member", "linux_raid_member", "iso9660", "udf", "squashfs"}:
            # A nonempty identifier alone cannot establish that a volume is in
            # the clear (for example a dataset inside a ZFS pool).
            indeterminate = True
    return kinds, indeterminate or not root_seen


def recovery_required(plan):
    """Add a displayable evidence summary to the private plan and return the consent requirement."""
    reasons = []
    kinds = set()
    unknown = False
    flagged = False
    try:
        guid, *_ = _esrt_resource()
        _, device, _ = fw.inventory(guid, devices=_local_rows("get_devices"))
        if guid != plan.get("guid") or device.get("DeviceId") != plan.get("device"):
            raise Hold("BIOSの対象が変わりました。")
        flagged = "affects-fde" in fw.strings(device, "Flags")
        report = fw.support_profile(fw.read_settings(), guid, device).get("encryption")
        reports = {"none": set(), "luks": {"luks"}, "bitlocker": {"bitlocker"},
                   "luks+bitlocker": {"luks", "bitlocker"}}
        if report is not None:
            if not isinstance(report, str) or report not in reports:
                unknown = True
            else:
                kinds.update(reports[report])
                if kinds:
                    reasons.append("機種別の設定に暗号化の申告があります。")
    except READ_ERRORS:
        unknown = True
    try:
        found, incomplete = _encrypted_volumes(fw.udisks_objects(), os.stat("/").st_dev)
        kinds.update(found)
        unknown |= incomplete
    except READ_ERRORS:
        unknown = True
    if flagged:
        reasons.append("fwupdは、この更新がディスク暗号化に影響する可能性を示しています。")
    if kinds:
        names = [name for key, name in (("luks", "LinuxのLUKS"), ("bitlocker", "WindowsのBitLocker"),
                                        ("other", "暗号化ボリューム")) if key in kinds]
        reasons.append("・".join(names) + "の回復手段を別端末または紙で参照できることを確認してください。")
    if unknown:
        reasons.append("暗号化の有無を確認しきれません。使用している場合は回復手段を確認してください。")
    plan["recovery_detail"] = " ".join(reasons)
    return flagged or bool(kinds) or unknown


def preflight(plan):
    """Return JSON-serializable binding. No mount, EFI, or power changes."""
    try:
        _platform()
        fw.check_marker(fw.marker_path())
        guid, raw, _, _, capsule_flags = _esrt_resource()
        _, device, devices = fw.inventory(guid)
        if (guid != plan.get("guid") or device["DeviceId"] != plan.get("device")
                or device["Version"] != plan.get("current") or not plan.get("version_format")
                or device.get("VersionFormat") != plan["version_format"] or raw is None
                or (device.get("VersionRaw") is not None and device["VersionRaw"] != raw)):
            raise Hold("実機のBIOS資源・現在版・版形式と計画が一致しません。")
        if plan.get("boot") and plan["boot"] != _uuid(fw.BOOT_ID):
            raise Hold("Linuxの起動が変わりました。最新の状態を確認してください。")
        if (fw.version_key(plan.get("target"), plan["version_format"])
                <= fw.version_key(device["Version"], plan["version_format"])):
            raise Hold("候補は実機BIOSより新しい版ではありません。")
        if type(plan.get("shutdown")) is not bool or (
                "needs-shutdown" in fw.strings(device, "Flags") and not plan["shutdown"]):
            raise Hold("必要な起動操作が計画と一致しません。")
        profile = fw.support_profile(fw.read_settings(), guid, device)
        history = fw.rows(["get-history"], allow_empty=True)
        if _daemon_busy():
            raise Hold("fwupdが別の処理を実行中です。")
        esp, partuuid, secure, capability = fw.check_ready(device, devices, history, profile)
        if fw.disk_delivery_requested():
            raise Hold("既存のディスク経由カプセル配送指示があります。")
        mounts = fw.mount_points()
        if fw.find_esp(mounts) != (esp, partuuid) or mounts[str(esp)].read_only:
            raise Hold("書き込み可能な同じEFI配送区画を確認できません。")
        route = _bound_route(esp, partuuid, mounts, plan, profile, capability, capsule_flags)
        if route["secure_boot"] != secure:
            raise Hold("Secure Bootの状態が変わりました。")
        if route["delivery"] != "capsule-on-disk" and fw.esp_has_entry(esp, route["file"], directory=False):
            raise Hold("予定のBIOSファイルがESPに既に存在します。")
        if "binding" in plan and route != plan["binding"]:
            raise Hold("配送先・起動先またはローダーが承認時から変わりました。")
        _power(profile, device)
        size = plan.get("payload_size")
        if type(size) is not int or size <= 0 or not SHA256.fullmatch(plan.get("payload_sha256") or ""):
            raise Hold("承認対象のカプセルの長さ・ハッシュを確認できません。")
        minimum = profile.get("esp_free_bytes", 0)
        if type(minimum) is not int or minimum < 0:
            raise Hold("ESPの必要空き容量の設定を確認できません。")
        required = max(minimum, 2 * size + 1024 * 1024)
        if shutil.disk_usage(esp).free < required:
            raise Hold(f"EFIシステム区画の空き容量が不足しています（必要 {required:,} バイト）。")
        return route
    except Hold:
        raise
    except READ_ERRORS as exc:
        raise Hold("準備条件を確認できません。 " + fw.visible(exc)) from exc


def check_power_action(plan, observation):
    """Validate Engine.power_check's fresh, private observation on each request.

    observe(plan) has just re-read the capsule contents, EFI routes, ESRT,
    attached devices and power. The service HMACs its UUID before passing this
    result here. Do not use GUI state or an observation from a previous request.
    """
    if (not observation.get("boot") or not plan.get("boot")
            or (observation["boot"] != plan["boot"] and not plan.get("machine"))
            or observation.get("machine") != plan.get("machine")
            or observation.get("device") != plan.get("device") or observation.get("guid") != plan.get("guid")):
        raise Hold("承認したPC・起動・BIOS資源と一致しません。")
    action = "shutdown" if plan.get("shutdown") else "reboot"
    if (not observation["can_identify"] or observation["current"] != plan["current"]
            or observation["version_format"] != plan.get("version_format")
            or observation["reservation"] != "matching" or observation["running"] is not False
            or observation["new_failure"] or observation["power"] != action):
        raise Hold(observation["detail"] or "予約・給電・起動操作の一致を確認できません。")
    return action
