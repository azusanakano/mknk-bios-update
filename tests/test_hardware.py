"""Synthetic EFI boot records and regular-file sysfs fixtures; no host access."""

import hashlib
import os
import stat
import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from test_engine import Machine

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import hardware as hw
from engine import Engine
from journal import Journal

fw = hw.fw
GUID = "156ae31e-05bd-41cf-833d-d47e8534dc7e"
PART = "281b1924-0635-43ac-b75a-da7dc9acc83a"
MACHINE = "f8808e2b-2a4e-4658-a3e5-600037b18795"
BOOT = "8d65e75b-3a14-461f-a285-1e7d423ce337"


def file_path(name, partition=PART, number=1, start=2048, size=32768):
    hd = struct.pack("<BBHIQQ16sBB", 4, 1, 42, number, start, size,
                     uuid.UUID(partition).bytes_le, 2, 2)
    encoded = ("\\" + name.replace("/", "\\") + "\0").encode("utf-16-le")
    return hd + struct.pack("<BBH", 4, 4, len(encoded) + 4) + encoded + b"\x7f\xff\x04\x00"


def boot_option(label, path, args=b""):
    return struct.pack("<IH", 1, len(path)) + (label + "\0").encode("utf-16-le") + path + args


class ObservationTest(unittest.TestCase):
    def fake(self, obj, name, *args, **kwargs):
        return self.enterContext(patch.object(obj, name, *args, **kwargs))

    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp)
        for key in ("ESRT", "DMI", "EFIVARS", "POWER", "LOCK_DIR", "LEGACY_LOCK_DIR"):
            path = self.root / key
            path.mkdir()
            self.fake(fw, key, path)
        self.fake(fw, "BOOT_ID", self.root / "boot-id")
        fw.BOOT_ID.write_text(BOOT)
        self.fake(fw, "EFI_PLATFORM_SIZE", self.root / "fw-platform-size")
        fw.EFI_PLATFORM_SIZE.write_text("64")
        self.esrt = fw.ESRT / "entry0"
        self.esrt.mkdir()
        for key, value in dict(fw_type="1", fw_class=GUID, fw_version="1", capsule_flags="0",
                               last_attempt_version="0", last_attempt_status="0").items():
            (self.esrt / key).write_text(value)
        dmi = dict(zip(fw.MODEL_FIELDS, ("Test Co", "Notebook", "NB-16", "Board", "rev-b")))
        for key, value in dict(dmi, bios_version="DMI-1", product_uuid=MACHINE).items():
            (fw.DMI / key).write_text(value)
        self.profile = {"dmi": dmi, "system_uuid_unique": True, "esrt_guid": GUID,
                        "bios_versions": ["1"], "secure_boot": {"delivery": "capsule-on-disk"},
                        "power": {"minimum_battery_percent": 25}}
        self.fake(fw, "read_settings", return_value=self.profile)
        self.esp = self.root / "ESP"
        self.esp.mkdir()
        self.mounts = {
            str(self.esp): fw.MountPoint(10, "8:1", "/", "vfat", False),
            str(fw.EFIVARS): fw.MountPoint(12, "0:1", "/", "efivarfs", False),
        }
        self.fake(fw, "mount_points", return_value=self.mounts)
        self.find_esp = self.fake(fw, "find_esp", return_value=(self.esp, PART))
        disk = self.root / "sysfs-disk"
        self.partition = disk / "partition"
        self.partition.mkdir(parents=True)
        self.block_size = disk / "queue/logical_block_size"
        self.block_size.parent.mkdir()
        self.block_size.write_text("512")
        for key, value in {"partition": "1", "start": "2048", "size": "32768"}.items():
            (self.partition / key).write_text(value)
        self.fake(fw, "partition_sysfs_path", return_value=self.partition)
        self.disk = self.fake(hw, "_physical_disk", return_value="disk-wwid-hash")
        self.fake(hw, "_platform")
        self.busy = self.fake(hw, "_daemon_busy", return_value=False)
        self.device = dict(Plugin="uefi_capsule", Protocols=[fw.PROTOCOL], Flags=["internal", "updatable"],
                           DeviceId="a" * 40, Guid=[GUID], Version="1", VersionFormat="number")
        self.devices = [self.device, {"DeviceId": "b" * 40, "Name": "SSD"}]
        self.history = []
        self.rows = self.fake(fw, "rows", side_effect=lambda args, **kw: self.devices if args == ["get-devices"]
                              else self.history)
        self.local = self.fake(hw, "_local_rows", side_effect=lambda op: self.devices if op == "get_devices"
                               else self.history)
        self.var("BootOrder", struct.pack("<H", 2))
        self.var("Boot0002", boot_option("Ubuntu", file_path("EFI/ubuntu/shimx64.efi")))
        self.var("SecureBoot", b"\x01")
        self.var("OsIndicationsSupported", struct.pack("<Q", 4))
        for supply, fields in {"AC": {"type": "Mains", "online": "1"},
                               "BAT0": {"type": "Battery", "capacity": "82", "present": "1"}}.items():
            (fw.POWER / supply).mkdir()
            for key, value in fields.items():
                (fw.POWER / supply / key).write_text(value)
        self.payload = b"fixture capsule"
        self.plan = dict(guid=GUID, device=self.device["DeviceId"], current="1", target="2",
                         target_raw=2, shutdown=False, version_format="number", boot=BOOT, machine=MACHINE,
                         payload_sha256=hashlib.sha256(self.payload).hexdigest(), payload_size=len(self.payload),
                         attempt_version=0, attempt_status=0)

    def var(self, name, payload, namespace=fw.EFI_GLOBAL):
        (fw.EFIVARS / f"{name}-{namespace}").write_bytes(struct.pack("<I", 7) + payload)

    def stage_cod(self):
        self.plan["binding"] = hw.preflight(self.plan)
        path = self.esp / self.plan["binding"]["file"]
        path.parent.mkdir(parents=True)
        path.write_bytes(self.payload)
        self.var("OsIndications", struct.pack("<Q", 4))
        return path

    def test_dmi_and_esrt_survive_missing_daemon(self):
        self.local.side_effect = FileNotFoundError("fwupd")
        self.var("BootNext", struct.pack("<H", 7))
        obs = hw.observe()
        self.assertEqual((obs["current"], obs["guid"]), ("DMI-1", GUID))
        self.assertIn("Notebook", obs["model"])
        self.assertEqual(obs["reservation"], "foreign")
        self.assertFalse(obs["can_identify"])
        self.assertIsNone(obs["running"])

    def test_model_instructions_require_exact_dmi_and_any_observed_guid(self):
        support = "https://vendor.example/notebook/update"
        recovery = "https://vendor.example/notebook/recovery"
        self.profile.update(support_url=support, recovery_url=recovery)
        obs = hw.observe()
        self.assertEqual((obs["support_url"], obs["recovery_url"]), (support, recovery))
        self.profile["esrt_guid"] = str(uuid.uuid4())
        obs = hw.observe()
        self.assertEqual((obs["support_url"], obs["recovery_url"]), ("", ""))
        (self.esrt / "fw_class").unlink()
        self.assertEqual(hw.observe()["support_url"], support)
        (fw.DMI / "board_version").write_text("different revision")
        self.assertEqual(hw.observe()["support_url"], "")

    def test_invalid_or_missing_instruction_url_preserves_other_link_and_firmware_state(self):
        self.stage_cod()
        self.profile["recovery_url"] = "https://vendor.example/support/recovery"
        for url in (None, ["bad"], "file:///tmp/fake", "https://user@vendor.example/recovery",
                    "https://vendor.example/a%2fb", "https://vendor.example/../recovery"):
            with self.subTest(url=url):
                self.profile["support_url"] = url
                obs = hw.observe(self.plan)
                self.assertEqual(obs["support_url"], "")
                self.assertEqual(obs["recovery_url"], self.profile["recovery_url"])
                self.assertEqual((obs["reservation"], obs["power"]), ("matching", "reboot"))

    def test_installed_version_is_independent_of_history_and_power_of_a_reservation(self):
        self.stage_cod()
        self.history.append(dict(DeviceId=self.device["DeviceId"], UpdateState=2, Releases=[dict(Version="2")]))
        obs = hw.observe(self.plan)
        self.assertEqual((obs["current"], obs["reservation"], obs["power"]), ("1", "matching", "reboot"))
        self.assertIn("目標 2", obs["history"])
        self.assertEqual(hw.check_power_action(self.plan, obs), "reboot")
        with self.assertRaises(hw.Hold):
            hw.check_power_action(self.plan, dict(obs, machine="another"))
        (fw.POWER / "BAT0" / "capacity").write_text("83")
        self.assertEqual(hw.check_power_action(self.plan, hw.observe(self.plan)), "reboot")
        (fw.POWER / "AC" / "online").write_text("0")
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "matching")
        with self.assertRaisesRegex(hw.Hold, "AC"):
            hw.check_power_action(self.plan, obs)

    def test_shutdown_requires_valid_file_and_physical_route(self):
        self.device["Flags"].append("needs-shutdown")
        with self.assertRaisesRegex(hw.Hold, "起動操作"):
            hw.preflight(self.plan)
        self.plan["shutdown"] = True
        path = self.stage_cod()
        obs = hw.observe(self.plan)
        self.assertEqual(hw.check_power_action(self.plan, obs), "shutdown")
        path.write_bytes(b"X" * len(self.payload))
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "unknown")
        with self.assertRaisesRegex(hw.Hold, "内容"):
            hw.check_power_action(self.plan, obs)
        path.write_bytes(self.payload)
        self.find_esp.side_effect = hw.Hold("複製区画")
        self.assertEqual(hw.observe(self.plan)["reservation"], "unknown")

    def test_extra_file_or_foreign_bootnext_never_activates(self):
        path = self.stage_cod()
        file = path.with_name("extra.cap")
        file.write_bytes(self.payload)
        self.assertFalse(hw.observe(self.plan)["power"])
        file.unlink()
        self.var("BootNext", struct.pack("<H", 2))
        self.assertEqual(hw.observe(self.plan)["reservation"], "foreign")

    def stage_cod_with_display(self):
        dib = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 0, 0, 0, 0)
        bmp = struct.pack("<2sIII", b"BM", 58, 0, 54) + dib + bytes(4)
        ux_guid = uuid.UUID(hw.UX_GUID).bytes_le
        capsule = bytearray(struct.pack("<16sIIIBBBBIII", ux_guid, 28, 0x10000, 44 + len(bmp),
                                        1, 0, 0, 0, 0, 0, 0) + bmp)
        capsule[29] = (-sum(capsule)) % 256
        normal = (fw.EFIVARS / f"Boot0002-{fw.EFI_GLOBAL}").read_bytes()
        self.profile["secure_boot"].update(esp_vendor_dir="ubuntu",
                                          normal_boot_entry_sha256=hashlib.sha256(normal).hexdigest(),
                                          ux_capsule_sha256=hashlib.sha256(capsule).hexdigest())
        bios = self.stage_cod()
        route = self.plan["binding"]
        display = self.esp / route["ux_file"]
        display.parent.mkdir(parents=True)
        display.write_bytes(capsule)
        # fwupd records the device's x86 capsule flags, even for the display asset.
        info = struct.pack("<I16sIQ16sI", 7, ux_guid, 0x50000, 0, bytes(16), 1)
        self.var("fwupd-ux-capsule", info + file_path(route["ux_file"]), fw.FWUPDATE_GUID)
        return bios, display

    def test_optional_display_registration_requires_the_verified_bitmap_and_bios(self):
        bios, display = self.stage_cod_with_display()
        capsule = display.read_bytes()
        self.assertEqual(hw.observe(self.plan)["reservation"], "matching")
        display.write_bytes(capsule[:-1] + b"!")
        self.assertFalse(hw.observe(self.plan)["power"])
        display.write_bytes(capsule)
        bios.unlink()
        self.assertFalse(hw.observe(self.plan)["power"])

    def test_completed_cod_with_only_its_verified_display_registration(self):
        bios, display = self.stage_cod_with_display()
        bios.unlink()
        self.var("OsIndications", struct.pack("<Q", 0))
        self.device["Version"] = "2"
        (self.esrt / "fw_version").write_text("2")
        self.assertNotEqual(hw.observe(self.plan)["reservation"], "clear")

        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "clear", obs["detail"])
        self.assertIn("表示", obs["prepare_block"])
        self.assertFalse(obs["power"])

        self.history.append(dict(DeviceId=self.device["DeviceId"], UpdateState=1))
        self.assertNotEqual(hw.observe(self.plan)["reservation"], "clear")
        self.history.clear()
        self.var("BootNext", struct.pack("<H", 2))
        self.assertEqual(hw.observe(self.plan)["reservation"], "foreign")
        (fw.EFIVARS / f"BootNext-{fw.EFI_GLOBAL}").unlink()
        display.unlink()
        self.assertEqual(hw.observe(self.plan)["reservation"], "unknown")

    def test_baseline_failure_and_unreadable_attempt_are_never_success(self):
        self.stage_cod()
        self.device["Version"] = "2"
        (self.esrt / "last_attempt_version").write_text("2")
        (self.esrt / "last_attempt_status").write_text("3")
        obs = hw.observe(self.plan)
        self.assertEqual(obs["current"], "2")
        self.assertTrue(obs["new_failure"])
        self.assertFalse(obs["power"])
        self.assertFalse(hw.observe(dict(self.plan, attempt_version=2, attempt_status=3))["new_failure"])
        self.assertFalse(hw.observe(dict(self.plan, target_raw=3))["new_failure"])
        self.assertFalse(hw.observe(dict(self.plan, target_raw=None))["attempt_comparable"])
        (self.esrt / "last_attempt_status").unlink()
        self.assertIsNone(hw.observe(self.plan)["attempt_status"])
        self.assertFalse(hw.observe(self.plan)["attempt_comparable"])

    def test_changed_failure_with_unrecorded_attempt_version_requires_review(self):
        capsule = self.stage_cod()
        platform = Machine()
        platform.observe = hw.observe
        actor = platform.actor(":1.2")
        journal = Journal(self.root / "journal")
        operation = dict(self.plan, machine=journal.machine_key(MACHINE), id="update", uid=actor.uid)
        journal.issue(operation, actor.sender, ":1.6", actor.bus)
        engine = Engine(journal, platform)
        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        (self.esrt / "last_attempt_status").write_text("3")

        pending = engine.status(actor)
        self.assertEqual(pending["state"], "hold")
        self.assertFalse(pending["can_power"])
        self.assertFalse(pending["can_replan"])

        capsule.unlink()
        self.var("OsIndications", struct.pack("<Q", 0))
        self.device["Version"] = "2"
        (self.esrt / "fw_version").write_text("2")
        cleared = engine.status(actor)
        self.assertEqual((cleared["state"], cleared["current"]), ("hold", "2"))
        self.assertTrue(cleared["can_replan"])
        self.assertIsNone(journal.active()["outcome"])

    def test_processed_cod_file_is_distinguished_after_boot(self):
        self.stage_cod()
        self.device["Version"] = "2"
        (self.esrt / "fw_version").write_text("2")
        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        self.var("OsIndications", struct.pack("<Q", 0))
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "clear")
        self.assertIn("残っています", obs["detail"])
        self.assertIn("カプセル", obs.get("prepare_block", ""))
        self.assertFalse(obs["power"])
        (self.esp / self.plan["binding"]["file"]).unlink()
        self.assertFalse(hw.observe(self.plan).get("prepare_block"))
        self.disk.return_value = "replacement-disk-with-cloned-partuuid"
        self.assertEqual(hw.observe(self.plan)["reservation"], "unknown")

    def test_cod_allows_the_same_physical_disk_to_be_renumbered_after_boot(self):
        self.stage_cod()
        self.mounts[str(self.esp)] = self.mounts[str(self.esp)]._replace(device="8:17")
        self.assertFalse(hw.observe(self.plan)["power"])

        self.device["Version"] = "2"
        (self.esrt / "fw_version").write_text("2")
        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        self.var("OsIndications", struct.pack("<Q", 0))
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "clear", obs["detail"])
        self.assertIn("カプセル", obs["prepare_block"])
        self.disk.return_value = "replacement-disk-with-cloned-partuuid"
        self.assertEqual(hw.observe(self.plan)["reservation"], "unknown")

    def test_verified_cod_route_can_follow_a_missing_boot_order_entry(self):
        self.var("BootOrder", struct.pack("<HH", 240, 2))
        with self.assertRaisesRegex(hw.Hold, "Boot00F0"):
            hw.preflight(self.plan)

        self.profile["secure_boot"]["boot_order_skip_missing"] = True
        self.stage_cod()
        obs = hw.observe(self.plan)
        self.assertEqual(hw.check_power_action(self.plan, obs), "reboot")

        self.var("Boot00F0", b"malformed")
        self.assertFalse(hw.observe(self.plan)["power"])
        self.var("Boot00F0", boot_option("Other ESP", file_path("EFI/other/loader.efi", partition=GUID)))
        self.assertFalse(hw.observe(self.plan)["power"])

    def test_verified_cod_route_holds_an_unreadable_or_malformed_first_boot_option(self):
        self.profile["secure_boot"]["boot_order_skip_missing"] = True
        self.var("BootOrder", struct.pack("<HH", 240, 2))
        boot_path = bytearray(file_path("EFI/ubuntu/shimx64.efi"))
        boot_path[-6:-4] = b"xx"  # Correct framing, but File() has no UTF-16 terminator.
        self.var("Boot00F0", boot_option("Ubuntu", boot_path))
        with self.assertRaisesRegex(hw.Hold, "Boot00F0"):
            hw.preflight(self.plan)

        (fw.EFIVARS / f"Boot00F0-{fw.EFI_GLOBAL}").unlink()
        self.stage_cod()

        read = fw.read_efi_variable

        def deny_one_variable(path):
            if path.name.startswith("Boot00F0-"):
                raise PermissionError("Boot00F0 unreadable")
            return read(path)

        with patch.object(fw, "read_efi_variable", side_effect=deny_one_variable):
            obs = hw.observe(self.plan)
        self.assertFalse(obs["power"])
        self.assertIn("Boot00F0 unreadable", obs["detail"])

    def test_completed_cod_file_stays_visible_after_reopen_but_foreign_changes_hold(self):
        capsule = self.stage_cod()
        self.device["Version"] = "2"
        (self.esrt / "fw_version").write_text("2")
        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        self.var("OsIndications", struct.pack("<Q", 0))
        platform = Machine()
        platform.observe = hw.observe
        actor = platform.actor(":1.2")
        journal = Journal(self.root / "journal")
        journal.issue(dict(self.plan, machine=journal.machine_key(MACHINE), id="completed", uid=actor.uid),
                      actor.sender, ":1.6", actor.bus)
        engine = Engine(journal, platform)
        self.assertEqual(engine.status(actor)["state"], "complete")

        engine = Engine(Journal(journal.path), platform)
        status = engine.status(actor)
        self.assertEqual(status["state"], "complete")
        self.assertTrue(status["can_check"])
        self.assertFalse(status["can_power"])
        self.assertIn("残っています", status["detail"])
        platform.candidate.update(guid=GUID, current="2", version_format="number", target="3")
        checked = engine.check(actor)
        self.assertEqual((checked["state"], checked["target"]), ("hold", "3"))
        self.assertTrue(checked["can_check"])
        self.assertFalse(checked["can_prepare"])
        self.assertIn("カプセル", checked["detail"])
        with self.assertRaises(hw.Hold):
            hw.preflight(dict(self.plan, boot=fw.BOOT_ID.read_text(), current="2", target="3"))

        for change in ("foreign-capsule", "new-delivery-flag", "new-machine"):
            with self.subTest(change=change):
                if change == "foreign-capsule":
                    capsule.write_bytes(b"other firmware")
                elif change == "new-delivery-flag":
                    self.var("OsIndications", struct.pack("<Q", 4))
                else:
                    (fw.DMI / "product_uuid").write_text(str(uuid.uuid4()))
                status = engine.status(actor)
                self.assertEqual(status["state"], "hold")
                self.assertFalse(status["can_check"])
                self.assertFalse(status["can_power"])
                capsule.write_bytes(self.payload)
                self.var("OsIndications", struct.pack("<Q", 0))
                (fw.DMI / "product_uuid").write_text(MACHINE)

    def test_read_failure_keeps_independent_evidence(self):
        actual = fw.esp_has_entry
        def phase(esp, relative, **kw):
            if relative == fw.DELL_RECOVERY_FILE:
                raise PermissionError("recovery unreadable")
            return actual(esp, relative, **kw)
        self.stage_cod()
        self.fake(fw, "esp_has_entry", side_effect=phase)
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "unknown")
        self.assertIn("recovery unreadable", obs["detail"])
        self.assertIn("配送ファイル", obs["detail"])

    def test_no_individual_identity_without_attestation(self):
        self.assertEqual(hw.observe()["machine"], MACHINE)
        self.profile.pop("system_uuid_unique")
        self.assertEqual(hw.observe()["machine"], "")
        self.profile["system_uuid_unique"] = True
        (fw.DMI / "product_uuid").write_text("00000000-0000-0000-0000-000000000000")
        self.assertEqual(hw.observe()["machine"], "")

    def test_fwupd_display_without_matching_esrt_never_proves_installation(self):
        self.plan["binding"] = hw.preflight(self.plan)
        self.device["Version"] = self.plan["target"]
        self.assertEqual(hw.observe(self.plan)["current"], "2")
        self.assertFalse(hw.observe(self.plan)["can_identify"])
        (self.esrt / "fw_version").write_text("2")
        self.assertTrue(hw.observe(self.plan)["can_identify"])
        self.device["VersionRaw"] = 1
        self.assertFalse(hw.observe(self.plan)["can_identify"])

    def test_equivalent_version_spelling_still_requires_matching_esrt_raw(self):
        self.plan.update(target="002", target_raw=2)
        self.stage_cod()
        self.device["Version"] = "2"
        fw.BOOT_ID.write_text(str(uuid.uuid4()))
        self.var("OsIndications", struct.pack("<Q", 0))
        self.assertFalse(hw.observe(self.plan)["can_identify"])
        (self.esrt / "fw_version").write_text("2")
        status = hw.observe(self.plan)
        self.assertTrue(status["can_identify"])
        self.assertEqual(status["reservation"], "clear")

    def test_foreign_update_and_low_battery_hold_preparation(self):
        self.history.append(dict(DeviceId="b" * 40, UpdateState=1))
        self.assertEqual(hw.observe()["reservation"], "foreign")
        with self.assertRaisesRegex(hw.Hold, "起動待ち"):
            hw.preflight(self.plan)
        self.history.clear()
        (fw.POWER / "BAT0" / "capacity").write_text("24")
        with self.assertRaisesRegex(hw.Hold, "25%"):
            hw.preflight(self.plan)
        (fw.POWER / "BAT0" / "present").write_text("0")
        self.profile["power"] = {"batteryless": True}
        hw.preflight(self.plan)
        self.profile["esp_free_bytes"] = 2**60
        with self.assertRaisesRegex(hw.Hold, "空き容量"):
            hw.preflight(self.plan)

    def stage_nvram(self, secure, registration_flags=0x50000):
        self.var("SecureBoot", bytes([secure]))
        self.profile["secure_boot"] = {"delivery": "shim" if secure else "nvram",
                                       "efi_app_dir": str(self.root), "esp_vendor_dir": "ubuntu"}
        dos = bytearray(64)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 60, 64)
        coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664, 1, 0, 0, 0, 112, 0x22)
        optional = bytearray(112)
        struct.pack_into("<H", optional, 0, 0x20b)
        struct.pack_into("<H", optional, 68, 10)
        loader = bytes(dos) + coff + optional + bytes(40)
        (self.root / ("fwupdx64.efi.signed" if secure else "fwupdx64.efi")).write_bytes(loader)
        if secure:
            (self.root / "shimx64.efi.signed").write_bytes(loader)
            digest = hashlib.sha256(loader).hexdigest()
            self.profile["secure_boot"].update(fwupd_efi_sha256=digest, shim_sha256=[digest])
            shim = self.esp / "EFI/ubuntu/shimx64.efi"
            shim.parent.mkdir(parents=True)
            shim.write_bytes(loader)
        route = hw.preflight(self.plan)
        self.plan["binding"] = route
        image = self.esp / route["file"]
        image.parent.mkdir(parents=True)
        image.write_bytes(self.payload)
        (self.esp / route["loader"]).write_bytes(loader)
        self.var("BootNext", struct.pack("<H", 7))
        info = struct.pack("<I16sIQ16sI", 7, uuid.UUID(GUID).bytes_le, registration_flags, 0, bytes(16), 1)
        self.var(f"fwupd-{GUID}-0", info + file_path(route["file"]), fw.FWUPDATE_GUID)
        return route, info

    def test_nvram_requires_device_file_loader_and_the_registered_partition(self):
        route, info = self.stage_nvram(False)
        self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"])))
        obs = hw.observe(self.plan)
        self.assertEqual(obs["reservation"], "matching", obs["detail"])
        self.assertEqual(hw.check_power_action(self.plan, obs), "reboot")
        self.var(f"fwupd-{GUID}-0", info + file_path(route["file"], number=2), fw.FWUPDATE_GUID)
        with self.assertRaisesRegex(hw.Hold, "ESP"):
            hw.check_power_action(self.plan, hw.observe(self.plan))

    def test_nvram_requires_current_lbas_in_both_paths_even_for_a_legacy_plan(self):
        route, info = self.stage_nvram(False)
        registration = f"fwupd-{GUID}-0"
        legacy = dict(self.plan, binding={k: v for k, v in route.items() if k not in ("start_lba", "size_lba")})
        for plan in (self.plan, legacy):
            self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"])))
            self.var(registration, info + file_path(route["file"]), fw.FWUPDATE_GUID)
            self.assertEqual(hw.check_power_action(plan, hw.observe(plan)), "reboot")
            self.var(registration, info + file_path(route["file"], start=4096), fw.FWUPDATE_GUID)
            self.assertFalse(hw.observe(plan)["power"])
            self.var(registration, info + file_path(route["file"]), fw.FWUPDATE_GUID)
            self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"], size=65536)))
            self.assertFalse(hw.observe(plan)["power"])

    def test_nvram_checks_4k_disk_geometry_in_logical_blocks(self):
        self.block_size.write_text("4096")
        route, info = self.stage_nvram(False)
        self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"], start=256, size=4096)))
        self.var(f"fwupd-{GUID}-0", info + file_path(route["file"], start=256, size=4096), fw.FWUPDATE_GUID)
        self.assertEqual(hw.check_power_action(self.plan, hw.observe(self.plan)), "reboot")

        (self.partition / "start").write_text("2049")
        self.assertFalse(hw.observe(self.plan)["power"])

    def test_fmp_image_instance_is_independent_of_linux_esrt_registration(self):
        self.profile["fmp"] = dict(image_type_id=GUID, image_index=1, hardware_instance=7)
        image = struct.pack("<I16sB3xIIQ", 2, uuid.UUID(GUID).bytes_le, 1, 1, 0, 7) + b"x"
        fmp = struct.pack("<IHHQ", 1, 0, 1, 16) + image
        self.payload = fw.FMP_CAPSULE + struct.pack("<III", 28, 0, 28 + len(fmp)) + fmp
        self.assertEqual(fw.check_capsule_scope(self.payload, GUID, self.profile), "FMP画像1件")
        self.plan.update(payload_sha256=hashlib.sha256(self.payload).hexdigest(), payload_size=len(self.payload))
        route, info = self.stage_nvram(False)
        self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"])))
        obs = hw.observe(self.plan)
        self.assertEqual(hw.check_power_action(self.plan, obs), "reboot")

        legacy = dict(route)
        legacy["instance"] = legacy.pop("fmp_instance")
        del legacy["registration_instance"]
        self.assertEqual(hw.observe(dict(self.plan, binding=legacy))["power"], "reboot")

        registration = fw.EFIVARS / f"fwupd-{GUID}-0-{fw.FWUPDATE_GUID}"
        registration.unlink()
        other_info = bytearray(info)
        struct.pack_into("<Q", other_info, 24, 7)
        self.var(f"fwupd-{GUID}-7", other_info + file_path(route["file"]), fw.FWUPDATE_GUID)
        self.assertFalse(hw.observe(self.plan)["power"])
        self.profile["fmp"]["hardware_instance"] = 0
        with self.assertRaises(hw.Hold):
            fw.check_capsule_scope(self.payload, GUID, self.profile)

    def test_nvram_flags_must_match_the_esrt_and_approved_registration(self):
        # fwupd only supplies BOTH x86 reset flags when NEITHER is present.
        (self.esrt / "capsule_flags").write_text("0x10041")
        route, info = self.stage_nvram(False, registration_flags=0x10041)
        self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["loader"])))
        self.assertEqual(hw.check_power_action(self.plan, hw.observe(self.plan)), "reboot")

        saved_info = info + file_path(route["file"])
        changed = bytearray(saved_info)
        struct.pack_into("<I", changed, 20, 0x50041)
        self.var(f"fwupd-{GUID}-0", changed, fw.FWUPDATE_GUID)
        self.assertFalse(hw.observe(self.plan)["power"])
        self.var(f"fwupd-{GUID}-0", saved_info, fw.FWUPDATE_GUID)

        (self.esrt / "capsule_flags").write_text("0x40041")
        self.assertFalse(hw.observe(self.plan)["power"])
        (self.esrt / "capsule_flags").write_text("0x10041")
        legacy_route = dict(route)
        legacy_route.pop("capsule_flags", None)
        legacy = dict(self.plan, binding=legacy_route)
        observed = hw.observe(legacy)
        self.assertEqual(observed["power"], "reboot", observed["detail"])
        self.assertEqual(hw.check_power_action(legacy, observed), "reboot")
        self.assertFalse(hw.observe(dict(legacy, binding=dict(legacy_route, loader_sha256="0" * 64)))["power"])
        self.var(f"fwupd-{GUID}-0", changed, fw.FWUPDATE_GUID)
        self.assertFalse(hw.observe(legacy)["power"])
        self.var(f"fwupd-{GUID}-0", saved_info, fw.FWUPDATE_GUID)
        (self.esrt / "capsule_flags").unlink()
        self.assertFalse(hw.observe(legacy)["power"])
        (fw.EFIVARS / f"BootNext-{fw.EFI_GLOBAL}").unlink()
        (fw.EFIVARS / f"fwupd-{GUID}-0-{fw.FWUPDATE_GUID}").unlink()
        self.assertEqual(hw.observe(legacy)["reservation"], "clear")

    def test_nvram_preflight_requires_readable_esrt_capsule_flags(self):
        (self.esrt / "capsule_flags").unlink()
        with self.assertRaisesRegex(hw.Hold, "フラグ"):
            self.stage_nvram(False)

    def test_secure_boot_shim_load_option_matches_fwupd_2_0_20(self):
        route, _ = self.stage_nvram(True)
        for path in ("\\fwupdx64.efi\0", "fwupdx64.efi\0"):
            with self.subTest(path=path):
                self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["shim"]),
                                                path.encode("utf-16-le")))
                obs = hw.observe(self.plan)
                self.assertEqual(obs["reservation"], "matching", obs["detail"])
                self.assertEqual(hw.check_power_action(self.plan, obs), "reboot")
        self.var("Boot0007", boot_option("Linux Firmware Updater", file_path(route["shim"]),
                                        "\\different.efi\0".encode("utf-16-le")))
        self.assertEqual(hw.observe(self.plan)["reservation"], "unknown")

    def test_recovery_prompt_uses_local_media_flag_and_operator_report(self):
        block = fw.UDISKS + ".Block"
        volumes = {"/root": {block: {"DeviceNumber": os.stat("/").st_dev, "HintSystem": True, "IdType": "ext4"}},
                   "/usb": {block: {"DeviceNumber": 7, "HintSystem": False, "IdType": "crypto_LUKS"}}}
        disks = self.fake(fw, "udisks_objects", return_value=volumes)
        self.assertFalse(hw.recovery_required(self.plan))
        self.assertEqual(self.plan["recovery_detail"], "")
        self.device["Flags"].append("affects-fde")
        self.assertTrue(hw.recovery_required(self.plan))
        self.assertIn("fwupd", self.plan["recovery_detail"])
        self.device["Flags"].remove("affects-fde")
        volumes["/root"][block]["CryptoBackingDevice"] = "/luks"
        volumes["/luks"] = {block: {"HintSystem": True, "IdType": "crypto_LUKS"}}
        volumes["/windows"] = {block: {"HintSystem": True, "IdType": "BitLocker"}}
        self.profile["encryption"] = "none"
        self.assertTrue(hw.recovery_required(self.plan))
        self.assertIn("LUKS", self.plan["recovery_detail"])
        self.assertIn("BitLocker", self.plan["recovery_detail"])
        volumes.pop("/windows")
        self.profile["encryption"] = "bitlocker"
        self.assertTrue(hw.recovery_required(self.plan))
        self.assertIn("申告", self.plan["recovery_detail"])
        self.assertIn("BitLocker", self.plan["recovery_detail"])
        disks.side_effect = hw.Hold("daemon offline")
        self.assertTrue(hw.recovery_required(self.plan))
        self.assertIn("確認しきれません", self.plan["recovery_detail"])

    def test_power_request_uses_one_fresh_capsule_and_route_read(self):
        self.stage_cod()
        verify = self.fake(hw, "_matches_file", wraps=hw._matches_file)
        self.find_esp.reset_mock()
        self.assertEqual(hw.check_power_action(self.plan, hw.observe(self.plan)), "reboot")
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(self.find_esp.call_count, 1)

    def test_gui_marker_requires_same_boot_exact_id_protected_metadata_and_no_legacy_request(self):
        self.stage_cod()
        self.plan["id"] = str(uuid.uuid4())
        marker = fw.marker_path()
        marker.mkdir(mode=0o700)
        path = marker / "gui-operation"
        path.write_bytes(self.plan["id"].encode() + b"\n")
        # The Windows test runner cannot open relative to a POSIX directory fd
        # or create root-owned inodes. Supply those results for this call only.
        metadata = {10: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0),
                    11: SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)}
        posix = Mock(O_RDONLY=0, O_NONBLOCK=2048, O_DIRECTORY=65536, O_NOFOLLOW=131072)
        def opened(name, flags, dir_fd=None):
            self.assertTrue(flags & posix.O_NOFOLLOW)
            if name == marker and dir_fd is None and flags & posix.O_DIRECTORY:
                return 10
            self.assertEqual((name, dir_fd), ("gui-operation", 10))
            return 11
        posix.open.side_effect = opened
        posix.fstat.side_effect = metadata.__getitem__
        posix.read.side_effect = lambda fd, n: path.read_bytes()[:n]
        reader = hw._owns_marker
        def read_marker(*args):
            with patch.object(hw, "os", posix):
                return reader(*args)
        self.fake(hw, "_owns_marker", side_effect=read_marker)
        self.assertEqual(hw.observe(self.plan)["reservation"], "matching")
        with self.assertRaisesRegex(hw.Hold, "既に"):
            hw.preflight(self.plan)
        self.assertEqual(hw.observe(dict(self.plan, boot=str(uuid.uuid4())))["reservation"], "foreign")
        self.assertEqual(hw.observe(dict(self.plan, id=str(uuid.uuid4())))["reservation"], "foreign")
        metadata[11].st_uid = 1000
        self.assertEqual(hw.observe(self.plan)["reservation"], "foreign")
        metadata[11].st_uid = 0
        metadata[10].st_mode |= 0o020
        self.assertEqual(hw.observe(self.plan)["reservation"], "foreign")
        metadata[10].st_mode &= ~0o020
        (fw.LEGACY_LOCK_DIR / marker.name).touch()
        self.assertEqual(hw.observe(self.plan)["reservation"], "foreign")


if __name__ == "__main__":
    unittest.main()
