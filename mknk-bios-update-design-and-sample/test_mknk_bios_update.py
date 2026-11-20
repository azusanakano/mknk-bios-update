"""Regression tests for the sample. No firmware, network or system bus access."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
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
                struct.pack("<II16sIQ16xI", 7, 7, guid.bytes_le, 0, 0, 1))
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
                  patch.object(updater, "marker_path", return_value=base / "marker"),
                  patch.object(updater, "rows", return_value=history),
                  redirect_stdout(result)):
                updater.main()
            self.assertIn("BIOS対象1件", result.getvalue())
            self.assertIn("配送指示とカプセルあり", result.getvalue())
            self.assertIn("Boot0003", result.getvalue())
            self.assertIn("成功", result.getvalue())


class InteractiveCandidateTest(unittest.TestCase):
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
