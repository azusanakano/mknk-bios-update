"""Regression tests for the sample. No firmware, network or system bus access."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.request import Request
import uuid
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).with_name("mknk-bios-update.py")
SPEC = importlib.util.spec_from_file_location("mknk_bios_update", SCRIPT)
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


class BiosSelectionTest(unittest.TestCase):
    def test_explicit_id_must_match_the_identified_bios(self):
        bios = {"DeviceId": "b" * 40, "Version": "1.0"}
        remote = {"Id": "lvfs"}
        with (patch.object(sys, "argv", [SCRIPT.name, "--apply", "--device-id=" + "a" * 40]),
              patch.object(sys.stdin, "isatty", return_value=True),
              patch.object(sys.stdout, "isatty", return_value=True),
              patch.object(updater.os.path, "isfile", return_value=True),
              patch.object(updater, "ESRT") as esrt,
              patch.object(updater, "read_settings", return_value={}),
              patch.object(updater, "stable_remote", return_value=remote),
              patch.object(updater, "command"),
              patch.object(updater, "inventory", return_value=("bios-guid", bios, [bios])),
              patch.object(updater, "check_ready", side_effect=AssertionError("checked for install")),
              redirect_stderr(io.StringIO())):
            esrt.is_dir.return_value = True
            try:
                with self.assertRaisesRegex(updater.Hold, "Device ID"):
                    updater.main()
            except SystemExit as exc:
                self.fail(f"The apply entry point could not validate the supplied ID: {exc.code}")


class CapsuleScopeTest(unittest.TestCase):
    guid = uuid.UUID("12345678-1234-1234-1234-123456789abc")
    fmp_guid = uuid.UUID("6dcbd5ed-e82d-4c44-bda1-7194199ad92a")

    @staticmethod
    def capsule(guid, body):
        return struct.pack("<16sIII", guid.bytes_le, 28, 0, 28 + len(body)) + body

    def single_image(self, count=1):
        sample = b"test fixture"
        image = struct.pack("<I16sB3xIIQ", 2, self.guid.bytes_le, 1, len(sample), 0, 0)
        return self.capsule(self.fmp_guid, struct.pack("<IHHQ", 1, 0, count, 16) + image + sample)

    def test_single_image_inside_an_esrt_capsule_matches_verified_profile(self):
        profile = {"fmp": {"image_type_id": str(self.guid), "image_index": 1, "hardware_instance": 0}}
        payload = self.capsule(self.guid, self.single_image())
        self.assertEqual(updater.check_capsule_scope(payload, str(self.guid), profile), "FMP画像1件")

    def test_capsule_header_with_unexpected_image_count_is_held(self):
        with self.assertRaises(updater.Hold):
            updater.check_capsule_scope(self.single_image(count=2), str(self.guid), {})

    def test_unverified_image_index_is_held(self):
        profile = {"fmp": {"image_type_id": str(self.guid), "image_index": 2, "hardware_instance": 0}}
        with self.assertRaises(updater.Hold):
            updater.check_capsule_scope(self.single_image(), str(self.guid), profile)

    def test_manifest_source_artifact_selects_the_firmware_file(self):
        release = ET.fromstring('''<release version="1.2.3">
          <artifacts><artifact type="source"><filename>image.rom</filename></artifact></artifacts>
          <checksum target="content" filename="firmware.bin" />
        </release>''')
        self.assertEqual(updater.firmware_payload_name(release), "image.rom")

    def test_cab_manifest_reads_the_default_release_when_older_images_are_bundled(self):
        manifest = b'''<component><id>example.bios</id><releases>
          <release version="131072"><checksum target="content" filename="new.bin"/></release>
          <release version="65536"><checksum target="content" filename="old.bin"/></release>
        </releases></component>'''
        with patch.object(updater, "read_cab_files", return_value={"bios.metainfo.xml": manifest}):
            self.assertEqual(updater.cab_manifest(Path("fixture.cab"), "example.bios"),
                             ("new.bin", "131072"))

    def test_cab_verification_checks_the_default_image_and_normalizes_its_version(self):
        manifest = b'''<component><id>example.bios</id><releases>
          <release version="131072"><checksum target="content" filename="new.bin"/></release>
          <release version="65536"><checksum target="content" filename="old.bin"/></release>
        </releases></component>'''
        guid = str(self.guid)
        device = {"DeviceId": "b" * 40, "VersionFormat": "pair"}
        candidate = {"Version": "2.0", "AppstreamId": "example.bios"}
        detail = {"AppstreamId": "example.bios", "Version": "131072", "Flags": ["trusted-payload"]}
        profile = {"fmp": {"image_type_id": guid, "image_index": 1, "hardware_instance": 0}}
        payload = self.single_image()
        with (patch.object(updater, "fwupd_query",
                           return_value=[{"Guid": [guid], "Releases": [detail]}]),
              patch.object(updater, "read_cab_files",
                           side_effect=[{"bios.metainfo.xml": manifest}, {"new.bin": payload}])):
            self.assertEqual(updater.verify_cab(Path("fixture.cab"), candidate, guid, device, [device], profile),
                             "FMP画像1件")


class StableRemoteTest(unittest.TestCase):
    def test_lvfs_label_without_an_approved_catalog_uri_is_held(self):
        remote = {"Id": "lvfs", "Enabled": True, "Kind": "download",
                  "MetadataUri": "https://catalog.invalid/unverified.xml.zst"}
        with patch.object(updater, "rows", return_value=[remote]):
            with self.assertRaises(updater.Hold):
                updater.stable_remote({})

    def test_distribution_stable_catalog_is_accepted(self):
        remote = {"Id": "lvfs", "Enabled": True, "Kind": "download",
                  "MetadataUri": "https://cdn.fwupd.org/downloads/firmware.xml.zst"}
        with patch.object(updater, "rows", return_value=[remote]):
            self.assertEqual(updater.stable_remote({}), remote)

    def test_catalog_policy_accepts_a_configured_mirror_and_checks_lvfs_channels(self):
        mirror = "https://mirror.invalid/catalog/stable.xml.zst"
        testing = "https://cdn.fwupd.org/downloads/firmware-testing.xml.zst"
        settings = {"stable_metadata_uris": [mirror, testing]}
        remote = {"Id": "lvfs", "Enabled": True, "Kind": "download", "MetadataUri": mirror}
        with patch.object(updater, "rows", return_value=[remote]):
            self.assertEqual(updater.stable_remote(settings), remote)
            remote["MetadataUri"] = testing
            with self.assertRaises(updater.Hold):
                updater.stable_remote(settings)


class StableCatalogTest(unittest.TestCase):
    metadata_uri = "https://cdn.fwupd.org/downloads/firmware.xml.xz"
    signature_uri = metadata_uri + ".jcat"
    guid = "12345678-1234-1234-1234-123456789abc"
    bios = {"DeviceId": "b" * 40, "Version": "1.0", "VersionFormat": "pair"}
    published = {"RemoteId": "lvfs", "AppstreamId": "example.bios", "Version": "2.0",
                 "Checksum": ["a" * 64]}
    signed_xml = b'''<components><component type="firmware"><id>example.bios</id>
      <provides><firmware type="flashed">12345678-1234-1234-1234-123456789abc</firmware></provides>
      <releases><release version="131072"><artifacts><artifact type="binary"><filename>bios.cab</filename>
      <checksum type="sha256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
      </artifact></artifacts></release></releases></component></components>'''

    def exercise_check(self, release, *, xml=None, metadata_result=None, expected_hold=None):
        remote = {"Id": "lvfs", "MetadataUri": self.metadata_uri, "MetadataUriSig": self.signature_uri}
        signed = lzma.compress(self.signed_xml if xml is None else xml)
        signature = b"signature fixture"
        bodies = {self.signature_uri: signature, self.metadata_uri: signed}
        requests = []
        daemon_calls = []

        def get(request, *, timeout):
            requests.append(request.full_url)
            return io.BytesIO(bodies[request.full_url])

        class FwupdError(Exception):
            domain = "FwupdError"

            def __init__(self, code):
                self.code = code
                self.message = "test metadata result"

        def update(remote_id, data, verification, _cancellable):
            daemon_calls.append((remote_id, data, verification))
            if metadata_result is not None:
                raise FwupdError(metadata_result)
            return True

        client = SimpleNamespace(update_metadata_bytes=update)
        fwupd = SimpleNamespace(Client=SimpleNamespace(new=lambda: client),
                                Error=SimpleNamespace(NOTHING_TO_DO=19))
        glib = SimpleNamespace(Bytes=SimpleNamespace(new=bytes), Error=FwupdError)
        imports = {"gi": SimpleNamespace(require_version=lambda *_args: None),
                   "gi.repository": SimpleNamespace(Fwupd=fwupd, GLib=glib)}
        with (TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output,
              patch.dict(sys.modules, imports),
              patch.object(sys, "argv", [SCRIPT.name, "--check"]),
              patch.object(updater.os.path, "isfile", return_value=True),
              patch.object(updater, "DMI", Path(tmp)),
              patch.object(updater, "ESRT", Path(tmp)),
              patch.object(updater, "read_settings", return_value={}),
              patch.object(updater, "stable_remote", return_value=remote),
              patch.object(updater, "command") as command,
              patch.object(updater, "inventory", return_value=(self.guid, self.bios, [self.bios])),
              patch.object(updater, "fwupd_query", return_value=[release]),
              patch.object(updater, "build_opener", return_value=SimpleNamespace(open=get))):
            if expected_hold is None:
                updater.main()
                self.assertIn("更新候補", output.getvalue())
            else:
                with self.assertRaisesRegex(updater.Hold, expected_hold):
                    updater.main()
                self.assertNotIn("更新候補", output.getvalue())
        command.assert_not_called()
        self.assertCountEqual(requests, [self.signature_uri, self.metadata_uri])
        self.assertEqual(daemon_calls, [("lvfs", signed, signature)])

    def test_check_uses_only_the_approved_lvfs_catalog(self):
        self.exercise_check(self.published)

    def test_reused_remote_id_does_not_authorize_an_unpublished_cab(self):
        self.exercise_check(dict(self.published, Checksum=["b" * 64]), expected_hold="署名済み")

    def test_container_hash_from_a_different_guid_does_not_prove_catalog_membership(self):
        foreign = self.signed_xml.replace(self.guid.encode(), b"00000000-0000-0000-0000-000000000001")
        self.exercise_check(self.published, xml=foreign, expected_hold="署名済み")

    def test_signature_rejection_stops_candidate_display(self):
        self.exercise_check(self.published, metadata_result=9, expected_hold="署名")

    def test_daemon_accepts_verified_signature_with_same_timestamp(self):
        self.exercise_check(self.published, metadata_result=19)


class BootEntryTest(unittest.TestCase):
    esp = uuid.UUID("87654321-4321-4321-4321-cba987654321")

    def boot_option(self, options=b""):
        device_path = struct.pack("<BBHIQQ16sBB", 4, 1, 42, 1, 64, 4096, self.esp.bytes_le, 2, 2)
        loader = "\\EFI\\example\\fwupdx64.efi\0".encode("utf-16-le")
        device_path += struct.pack("<BBH", 4, 4, len(loader) + 4) + loader + b"\x7f\xff\x04\x00"
        name = "Linux Firmware Updater\0".encode("utf-16-le")
        return struct.pack("<IIH", 7, 1, len(device_path)) + name + device_path + options

    def test_only_the_verified_boot_option_for_the_current_esp_is_reusable(self):
        expected = self.boot_option()
        profile = {"boot_entry_sha256": [hashlib.sha256(expected).hexdigest()]}
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            entry = Path(tmp) / f"Boot0003-{updater.EFI_GLOBAL}"
            entry.write_bytes(expected)
            updater.check_boot_entries(str(self.esp), profile)
            with self.assertRaises(updater.Hold):
                updater.check_boot_entries(str(uuid.UUID(int=1)), profile)
            entry.write_bytes(self.boot_option(b"different optional data"))
            with self.assertRaises(updater.Hold):
                updater.check_boot_entries(str(self.esp), profile)


class ReservationStatusTest(unittest.TestCase):
    @staticmethod
    def fwupd_variable(state, guid, *, include_device_path=True):
        info = struct.pack("<II16sIQ16xI", 7, 7, guid.bytes_le, 0, 0, state)
        if not include_device_path:
            return info
        hd = struct.pack("<BBHIQQ16sBB", 4, 1, 42, 1, 64, 4096, BootEntryTest.esp.bytes_le, 2, 2)
        name = "\\EFI\\example\\firmware.cap\0".encode("utf-16-le")
        return info + hd + struct.pack("<BBH", 4, 4, 4 + len(name)) + name + b"\x7f\xff\x04\x00"

    def test_status_reports_an_efi_reservation_even_with_success_history(self):
        guid = CapsuleScopeTest.guid
        bios = {"DeviceId": "b" * 40, "Version": "1.0"}
        history = [{"DeviceId": bios["DeviceId"], "UpdateState": 2,
                    "Releases": [{"Version": "2.0"}]}]
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}").write_bytes(
                self.fwupd_variable(1, guid))
            (variables / f"BootNext-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IH", 7, 3))
            esp = base / "esp"
            directory = esp / "EFI" / "UpdateCapsule"
            directory.mkdir(parents=True)
            (directory / "record.cap").touch()
            (variables / f"OsIndications-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            result = io.StringIO()
            with (patch.object(sys, "argv", [SCRIPT.name, "--status"]),
                  patch.object(updater.os.path, "isfile", return_value=True),
                  patch.object(updater, "EFIVARS", variables),
                  patch.object(updater, "mount_points", return_value={str(variables): ("0:1", "/", "efivarfs")}),
                  patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
                  patch.object(updater, "inventory", return_value=(str(guid), bios, [bios])),
                  patch.object(updater, "DMI", base / "no-host-data"),
                  patch.object(updater, "marker_path", return_value=base / "marker"),
                  patch.object(updater, "rows", return_value=history),
                  redirect_stdout(result)):
                updater.main()
            self.assertIn("BIOS対象1件", result.getvalue())
            self.assertIn("配送指示あり", result.getvalue())
            self.assertIn("配置先に項目あり（内容未確認）", result.getvalue())
            self.assertIn("Boot0003", result.getvalue())
            self.assertIn("成功", result.getvalue())

    def test_header_without_a_device_path_cannot_establish_reservation_state(self):
        guid = CapsuleScopeTest.guid
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            entry = Path(tmp) / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}"
            for state in (1, 2):
                with self.subTest(state=state):
                    entry.write_bytes(self.fwupd_variable(state, guid, include_device_path=False))
                    with self.assertRaisesRegex(updater.Hold, "デバイスパス"):
                        updater.nvram_reservations()

    def test_cleared_registration_with_valid_device_path_is_not_pending(self):
        guid = CapsuleScopeTest.guid
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            entry = Path(tmp) / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}"
            entry.write_bytes(self.fwupd_variable(0, guid))
            self.assertEqual(updater.nvram_reservations(), [])

    def test_status_prints_delivery_bit_even_when_esp_cannot_be_resolved(self):
        with (patch.object(updater, "mount_points", return_value={}),
              patch.object(updater, "require_efivarfs"),
              patch.object(updater, "nvram_reservations", return_value=[]),
              patch.object(updater, "boot_next", return_value=None),
              patch.object(updater, "find_esp", side_effect=updater.Hold("ESP is ambiguous")),
              patch.object(updater, "disk_delivery_requested", return_value=True),
              redirect_stdout(io.StringIO()) as output):
            updater.show_reservations(str(CapsuleScopeTest.guid))
        self.assertIn("配送指示あり", output.getvalue())
        self.assertIn("ESP is ambiguous", output.getvalue())

    def test_status_prints_bootnext_and_marker_when_inventory_fails(self):
        with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output:
            variables = Path(tmp)
            marker = variables / "marker"
            marker.touch()
            (variables / f"BootNext-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IH", 7, 3))
            with (patch.object(sys, "argv", [SCRIPT.name, "--status"]),
                  patch.object(updater.os.path, "isfile", return_value=True),
                  patch.object(updater, "inventory", side_effect=updater.Hold("inventory unavailable")),
                  patch.object(updater, "EFIVARS", variables),
                  patch.object(updater, "mount_points", return_value={str(variables): ("0:1", "/", "efivarfs")}),
                  patch.object(updater, "find_esp", return_value=(variables, str(BootEntryTest.esp))),
                  patch.object(updater, "marker_path", return_value=marker),
                  self.assertRaisesRegex(updater.Hold, "inventory unavailable")):
                updater.main()

        self.assertIn("Boot0003", output.getvalue())
        self.assertIn("この起動で更新を依頼しています", output.getvalue())

    def test_status_prints_marker_when_history_fails(self):
        bios = {"DeviceId": "b" * 40, "Version": "1.0"}
        with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output:
            marker = Path(tmp) / "marker"
            marker.touch()
            with (patch.object(sys, "argv", [SCRIPT.name, "--status"]),
                  patch.object(updater.os.path, "isfile", return_value=True),
                  patch.object(updater, "inventory", return_value=(str(CapsuleScopeTest.guid), bios, [bios])),
                  patch.object(updater, "DMI", Path(tmp)),
                  patch.object(updater, "show_reservations"),
                  patch.object(updater, "marker_path", return_value=marker),
                  patch.object(updater, "rows", side_effect=updater.Error("history unavailable")),
                  self.assertRaisesRegex(updater.Error, "history unavailable")):
                updater.main()
        self.assertIn("この起動で更新を依頼しています", output.getvalue())


class ReadinessTest(unittest.TestCase):
    def test_dell_recovery_file_blocks_preparation_without_delivery_bit(self):
        bios = {"DeviceId": "b" * 40, "Flags": ["updatable"]}
        with TemporaryDirectory() as tmp:
            esp = Path(tmp)
            previous = esp / "EFI/dell/bios/recovery/BIOS_TRS.rcv"
            previous.parent.mkdir(parents=True)
            previous.write_bytes(b"fixture")
            with (patch.object(updater, "mount_points", return_value={}),
                  patch.object(updater, "require_efivarfs"),
                  patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
                  patch.object(updater, "nvram_reservations", return_value=[]),
                  patch.object(updater, "boot_next", return_value=None),
                  patch.object(updater, "check_boot_entries"),
                  patch.object(updater, "disk_delivery_requested", return_value=False),
                  patch.object(updater, "check_power"),
                  self.assertRaisesRegex(updater.Hold, "BIOS_TRS.rcv")):
                updater.check_ready(bios, [bios], [], {})

    def test_usb_pd_pps_counts_as_external_power(self):
        with TemporaryDirectory() as tmp, patch.object(updater, "POWER", Path(tmp)):
            battery = Path(tmp) / "BAT0"
            battery.mkdir()
            (battery / "type").write_text("Battery", encoding="ascii")
            usb = Path(tmp) / "USB"
            usb.mkdir()
            (usb / "type").write_text("USB", encoding="ascii")
            for value in ("1", "2"):
                with self.subTest(online=value):
                    (usb / "online").write_text(value, encoding="ascii")
                    updater.check_power()
            (usb / "online").write_text("0", encoding="ascii")
            with self.assertRaises(updater.Hold):
                updater.check_power()


class EspSelectionTest(unittest.TestCase):
    guid = str(BootEntryTest.esp)
    block = "org.freedesktop.UDisks2.Block"
    partition = "org.freedesktop.UDisks2.Partition"
    filesystem = "org.freedesktop.UDisks2.Filesystem"
    lsblk = {"blockdevices": [{"maj:min": "8:1", "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                              "partuuid": guid}]}
    mounts = {str(Path("/boot/efi")): ("8:1", "/", "vfat")}

    def volume(self, kind, *, mount=b"/boot/efi\0", internal=True, raid="/", number=2049):
        return {
            self.block: {"IdType": "vfat", "HintSystem": internal, "DeviceNumber": number, "MDRaid": raid},
            self.partition: {"Type": kind, "UUID": self.guid},
            self.filesystem: {"MountPoints": [mount]},
        }

    def lookup(self, objects, mounts=None):
        with (patch.object(updater.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(self.lsblk))),
              patch.object(updater, "udisks_objects", return_value=objects, create=True),
              patch.object(updater.os, "major", new=lambda number: number >> 8, create=True),
              patch.object(updater.os, "minor", new=lambda number: number & 255, create=True)):
            return updater.find_esp(self.mounts if mounts is None else mounts)

    def test_rejects_a_second_partition_fwupd_could_choose(self):
        primary = self.volume(updater.ESP_TYPE)
        for kind, raid in (("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "/"),
                           ("0xef", "/"), ("", "/org/freedesktop/UDisks2/mdraid/example")):
            with self.subTest(kind=kind, raid=raid):
                other = self.volume(kind, mount=b"/mnt/other\0", raid=raid, number=2050)
                with self.assertRaisesRegex(updater.Hold, "配送区画"):
                    self.lookup({"/block/esp": primary, "/block/other": other})

    def test_ignores_external_basic_data_partition(self):
        primary = self.volume(updater.ESP_TYPE)
        other = self.volume("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                            mount=b"/media/usb\0", internal=False, number=2050)
        self.assertEqual(self.lookup({"/block/esp": primary, "/block/usb": other}),
                         (Path("/boot/efi"), self.guid))

    def test_requires_udisks_mount_to_match_locally_inspected_mount(self):
        with self.assertRaisesRegex(updater.Hold, "マウント"):
            self.lookup({"/block/esp": self.volume(updater.ESP_TYPE, mount=b"/mnt/other\0")})

    def test_rejects_an_overlay_mount_that_hides_a_delivery_directory(self):
        mounts = {**self.mounts, str(Path("/boot/efi/EFI")): ("8:3", "/", "ext4")}
        with self.assertRaisesRegex(updater.Hold, "マウント"):
            self.lookup({"/block/esp": self.volume(updater.ESP_TYPE)}, mounts=mounts)


class InteractiveCandidateTest(unittest.TestCase):
    def test_equivalent_triplet_versions_with_different_cabs_are_held(self):
        device = {"DeviceId": "b" * 40, "Version": "1.0.0", "VersionFormat": "triplet"}
        first = {"RemoteId": "lvfs", "AppstreamId": "example.bios", "Version": "1.02.3",
                 "Checksum": ["a" * 64]}
        second = dict(first, Version="1.2.3", Checksum=["b" * 64])
        with (patch.object(updater, "fwupd_query", return_value=[first, second]),
              self.assertRaisesRegex(updater.Hold, "異なる配布物")):
            updater.candidate(device)
        with patch.object(updater, "fwupd_query", return_value=[first, second]):
            self.assertEqual(updater.candidate(dict(device, VersionFormat="plain")), first)

    def test_query_exposes_a_release_requiring_update_action(self):
        names = ("REQUESTS", "REQUESTS_NON_GENERIC", "DETACH_ACTION", "UPDATE_ACTION",
                 "ALLOW_AUTHENTICATION", "FDE_WARNING", "SHOW_PROBLEMS")
        features = SimpleNamespace(**{name: 1 << bit for bit, name in enumerate(names)})
        release = {"RemoteId": "lvfs", "AppstreamId": "example.bios", "Version": "2.0",
                   "Flags": [], "Checksum": ["a" * 64]}

        class Client:
            flags = 0

            def set_feature_flags(self, enabled, _cancellable):
                self.flags = enabled
                return True

            def get_upgrades(self, _device_id, _cancellable):
                if self.flags & features.UPDATE_ACTION:
                    return [SimpleNamespace(to_json_string=lambda _flags: json.dumps(release))]
                return []

        bindings = SimpleNamespace(FeatureFlags=features, Client=SimpleNamespace(new=Client),
                                   CodecFlags=SimpleNamespace(NONE=0))
        imports = {"gi": SimpleNamespace(require_version=lambda *_args: None),
                   "gi.repository": SimpleNamespace(Fwupd=bindings, GLib=SimpleNamespace(Error=RuntimeError))}
        with patch.dict(sys.modules, imports), patch.object(updater, "rows", return_value=[]):
            self.assertEqual(updater.candidate({"DeviceId": "b" * 40, "Version": "1.0"}), release)


class CabDestinationTest(unittest.TestCase):
    def test_redirect_has_to_remain_in_an_approved_https_origin_and_path(self):
        original = Request("https://cdn.fwupd.org/downloads/package.cab")
        handler = updater.CabRedirectHandler(updater.cab_bases({}))
        for destination in ("http://cdn.fwupd.org/downloads/package.cab",
                            "https://outside.invalid/downloads/package.cab",
                            "https://cdn.fwupd.org/private/package.cab",
                            "https://cdn.fwupd.org/downloads/%2e%2e/private/package.cab"):
            with self.subTest(destination=destination), self.assertRaises(updater.Hold):
                handler.redirect_request(original, None, 302, "Found", {}, destination)
        destination = "https://fwupd.org/downloads/package.cab"
        redirected = handler.redirect_request(original, None, 302, "Found", {}, destination)
        self.assertEqual(redirected.full_url, destination)

    def test_disallowed_initial_cab_location_is_rejected_before_opening(self):
        digest = "a" * 64
        release = {"Locations": ["https://outside.invalid/package.cab"], "Checksum": [digest]}
        remote = {"MetadataUri": "https://cdn.fwupd.org/downloads/firmware.xml.zst"}
        with TemporaryDirectory() as tmp, patch.object(updater, "build_opener") as build:
            cab = Path(tmp) / "firmware.cab"
            with self.assertRaises(updater.Error):
                updater.fetch_cab(release, remote, cab, {})
            build.return_value.open.assert_not_called()
            self.assertFalse(cab.exists())
