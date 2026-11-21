"""Regression tests for the sample. No firmware, network or system bus access."""

from contextlib import nullcontext, redirect_stderr, redirect_stdout
from email.message import Message
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.response import addinfourl
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
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


class FixtureGLibError(Exception):
    pass


class FixtureRegex:
    @staticmethod
    def new(pattern, _compile_options, _match_options):
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise FixtureGLibError(str(exc)) from exc
        return SimpleNamespace(match=lambda text, _options: (compiled.search(text) is not None, None))


class StableCatalogTest(unittest.TestCase):
    metadata_uri = "https://cdn.fwupd.org/downloads/firmware.xml.xz"
    signature_uri = metadata_uri + ".jcat"
    guid = "12345678-1234-1234-1234-123456789abc"
    bios = {"DeviceId": "b" * 40, "Version": "1.0", "VersionFormat": "pair",
            "VendorIds": ["DMI:LENOVO"], "Protocols": ["org.uefi.capsule"]}
    published = {"RemoteId": "lvfs", "AppstreamId": "example.bios", "Version": "2.0",
                 "Checksum": ["a" * 64]}
    signed_xml = b'''<components><component type="firmware"><id>example.bios</id>
      <provides><firmware type="flashed">12345678-1234-1234-1234-123456789abc</firmware></provides>
      <releases><release version="131072"><artifacts><artifact type="binary"><filename>bios.cab</filename>
      <checksum type="sha256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</checksum>
      </artifact></artifacts></release></releases></component></components>'''

    def exercise_check(self, release, *, xml=None, metadata_result=None, expected_hold=None, expected_output=None,
                       host_ids=None, policy=(None, frozenset()), approval_required=False, daemon_version="2.0.20",
                       device_before_refresh=None):
        remote = {"Id": "lvfs", "MetadataUri": self.metadata_uri, "MetadataUriSig": self.signature_uri,
                  "ApprovalRequired": False}
        active_remote = dict(remote, ApprovalRequired=approval_required)
        signed = lzma.compress(self.signed_xml if xml is None else xml)
        signature = b"signature fixture"
        bodies = {self.signature_uri: signature, self.metadata_uri: signed}
        requests = []
        daemon_calls = []

        def get(request, *, timeout):
            requests.append(request.full_url)
            return io.BytesIO(bodies[request.full_url])

        class FwupdError(FixtureGLibError):
            domain = "FwupdError"

            def __init__(self, code):
                self.code = code
                self.message = "test metadata result"

        def update(remote_id, data, verification, _cancellable):
            daemon_calls.append((remote_id, data, verification))
            if metadata_result is not None:
                raise FwupdError(metadata_result)
            return True

        def inventory():
            device = self.bios if daemon_calls or device_before_refresh is None else device_before_refresh
            return self.guid, device, [device]

        client = SimpleNamespace(update_metadata_bytes=update, get_daemon_version=lambda: daemon_version)
        fwupd = SimpleNamespace(Client=SimpleNamespace(new=lambda: client),
                                Error=SimpleNamespace(NOTHING_TO_DO=19))
        glib = SimpleNamespace(Bytes=SimpleNamespace(new=bytes), Error=FixtureGLibError, Regex=FixtureRegex)
        imports = {"gi": SimpleNamespace(require_version=lambda *_args: None),
                   "gi.repository": SimpleNamespace(Fwupd=fwupd, GLib=glib)}
        with (TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output,
              patch.dict(sys.modules, imports),
              patch.object(sys, "argv", [SCRIPT.name, "--check"]),
              patch.object(updater.os.path, "isfile", return_value=True),
              patch.object(updater, "DMI", Path(tmp)),
              patch.object(updater, "ESRT", Path(tmp)),
              patch.object(updater, "read_settings", return_value={}),
              patch.object(updater, "stable_remote", side_effect=[remote, remote, active_remote]),
              patch.object(updater, "command", return_value=json.dumps(host_ids)) as command,
              patch.object(updater, "admin_checksums", return_value=policy) as admin,
              patch.object(updater, "inventory", side_effect=inventory),
              patch.object(updater, "fwupd_query", return_value=[release] if release else []),
              patch.object(updater, "build_opener", return_value=SimpleNamespace(open=get))):
            if expected_hold is None:
                updater.main()
                self.assertIn(expected_output or "更新候補  ", output.getvalue())
            else:
                with self.assertRaisesRegex(updater.Hold, expected_hold):
                    updater.main()
                self.assertNotIn("更新候補", output.getvalue())
        if host_ids is None:
            command.assert_not_called()
        else:
            command.assert_called_once_with(["hwids"])
        if approval_required:
            admin.assert_called_once_with(active_remote)
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

    def catalog_with_component_data(self, data):
        root = ET.fromstring(self.signed_xml)
        root.find("component").append(ET.fromstring(data))
        return ET.tostring(root)

    def test_check_accepts_the_vendor_requirement_used_by_public_thinkpad_metadata(self):
        # com.lenovo.SingleCapThinkPadN3YETXXW.firmware, LVFS stable 2026-11-20.
        xml = self.catalog_with_component_data(
            '<requires><firmware compare="regex" version="NVME:0x144D|NVME:0x14A4|NVME:0x1CC4|'
            'NVME:0x1E0F|NVME:0x8086|NVME:0x1E95|NVME:0x1179|NVME:0x1C5C|TBT:0x0109|'
            'DMI:LENOVO|NVME:0x15B7|NVME:0x1344|NVME:0x17AA">vendor-id</firmware>'
            '<id compare="ge" version="1.1.3">org.freedesktop.fwupd</id></requires>')
        with patch.object(self, "bios", dict(self.bios, VendorIds=["PCI:0x1234", "DMI:LENOVO"])):
            self.exercise_check(self.published, xml=xml, metadata_result=19)
        with patch.object(self, "bios", dict(self.bios, VendorIds=["DMI:OTHER"])):
            self.exercise_check(self.published, xml=xml, metadata_result=19, expected_hold="機種条件")

    def test_check_holds_when_the_vendor_id_cannot_be_verified(self):
        xml = self.catalog_with_component_data(
            '<requires><firmware compare="eq" version="DMI:LENOVO">vendor-id</firmware></requires>')
        self.exercise_check(self.published, xml=xml)
        bios = {key: value for key, value in self.bios.items() if key != "VendorIds"}
        with patch.object(self, "bios", bios):
            self.exercise_check(self.published, xml=xml, expected_hold="条件を確認できません")
        invalid = xml.replace(b'version="DMI:LENOVO"', b'version="["')
        self.exercise_check(self.published, xml=invalid, expected_hold="条件を確認できません")

    def test_checks_the_signed_current_bios_requirement_even_with_the_same_cab(self):
        for compare, version, expected_hold in (("lt", "1.0", "必須条件"), ("lt", "1.1", None),
                                                ("eq", "1.0", None), ("ne", "1.0", "必須条件")):
            with self.subTest(compare=compare, version=version):
                xml = self.catalog_with_component_data(
                    f'<requires><firmware compare="{compare}" version="{version}"/></requires>')
                self.exercise_check(self.published, xml=xml, metadata_result=19, expected_hold=expected_hold)

    def test_selected_candidate_is_held_when_a_signed_requirement_is_unknown(self):
        xml = self.catalog_with_component_data("<requires><phased_update>4</phased_update></requires>")
        self.exercise_check(self.published, xml=xml, metadata_result=19, expected_hold="必須条件")

    def test_fwupd_minimum_version_is_verified_for_a_selected_candidate(self):
        xml = self.catalog_with_component_data(
            '<requires><id compare="ge" version="2.0.20">org.freedesktop.fwupd</id></requires>')
        self.exercise_check(self.published, xml=xml, metadata_result=19)
        self.exercise_check(self.published, xml=xml, metadata_result=19,
                            daemon_version="2.0.19", expected_hold="必須条件")
        self.exercise_check(self.published, xml=xml, metadata_result=19,
                            daemon_version=None, expected_hold="必須条件")

    def test_check_evaluates_signed_recommends_and_suggests(self):
        for kind in ("recommends", "suggests"):
            with self.subTest(kind=kind):
                xml = self.catalog_with_component_data(
                    f'<{kind}><firmware compare="ge" version="1.0"/></{kind}>')
                self.exercise_check(self.published, xml=xml, metadata_result=19)
                unmet = xml.replace(b'version="1.0"', b'version="1.1"')
                self.exercise_check(self.published, xml=unmet, metadata_result=19, expected_hold="必須条件")

    def test_catalog_checks_the_signed_update_protocol_and_version_format(self):
        for key, compatible, incompatible in (
            ("LVFS::UpdateProtocol", "org.uefi.capsule", "org.usb.dfu"),
            ("LVFS::VersionFormat", "pair", "quad"),
        ):
            with self.subTest(key=key):
                xml = self.catalog_with_component_data(f'<custom><value key="{key}">{compatible}</value></custom>')
                self.exercise_check(self.published, xml=xml)
                mismatched = f'<custom><value key="{key}">{incompatible}</value></custom>'
                self.exercise_check(self.published, xml=self.catalog_with_component_data(mismatched),
                                    expected_hold="配布条件")
                self.exercise_check(self.published, xml=self.catalog_with_competitor("196608", component_data=mismatched))

    def test_catalog_version_formats_accept_fwupd_bcd_compatibility(self):
        xml = self.catalog_with_component_data(
            '<custom><value key="LVFS::VersionFormat">quad</value>'
            '<value key="LVFS::VersionFormat">pair</value></custom>')
        xml = xml.replace(b'release version="131072"', b'release version="2.0"')
        with patch.object(self, "bios", dict(self.bios, VersionFormat="bcd")):
            self.exercise_check(self.published, xml=xml)

    def test_check_uses_the_device_version_format_after_metadata_refresh(self):
        xml = self.catalog_with_component_data('<custom><value key="LVFS::VersionFormat">pair</value></custom>')
        before = dict(self.bios, Version="65536", VersionFormat="number")
        self.exercise_check(self.published, xml=xml, device_before_refresh=before, expected_output="1.0 → 2.0")

    def test_selected_candidate_uses_the_current_remote_approval_policy(self):
        self.exercise_check(self.published, approval_required=True, policy=(set(), set()),
                            expected_hold="承認一覧")
        self.exercise_check(self.published, approval_required=True, policy=({"a" * 64}, set()))

    def test_selected_candidate_is_checked_for_an_explicit_block_without_competitors(self):
        self.exercise_check(self.published, policy=(None, {"a" * 64}), expected_hold="明示ブロック")

    def catalog_with_competitor(self, version, *, component_data=None):
        root = ET.fromstring(self.signed_xml)
        component = root.find("component")
        competitor = ET.fromstring(ET.tostring(component))
        entry = competitor.find("releases/release")
        entry.set("version", version)
        entry.find(".//checksum").text = "b" * 64
        if component_data:
            competitor.append(ET.fromstring(component_data))
        root.append(competitor)
        return ET.tostring(root)

    def test_holds_when_index_omits_a_different_cab_for_the_same_version(self):
        self.exercise_check(self.published, xml=self.catalog_with_competitor("2.00"),
                            metadata_result=19, expected_hold="同じ版")

    def test_holds_when_index_omits_a_newer_version_without_an_exclusion(self):
        self.exercise_check(self.published, xml=self.catalog_with_competitor("196608"),
                            metadata_result=19, expected_hold="上位版")

    def test_no_index_candidate_does_not_hide_a_newer_catalog_release(self):
        self.exercise_check(None, expected_hold="上位版")

    def test_only_installed_version_in_catalog_means_no_update(self):
        self.exercise_check(None, xml=self.signed_xml.replace(b'version="131072"', b'version="65536"'),
                            expected_output="このBIOSで利用できる新版はありません")

    def test_check_reports_a_missing_model_separately_from_a_missing_update(self):
        self.exercise_check(None, xml=b"<components/>", expected_output="この機種の掲載を確認できません")
        xml = self.catalog_with_component_data(
            "<requires><hardware>33333333-3333-3333-3333-333333333333</hardware></requires>")
        self.exercise_check(None, xml=xml, expected_output="この機種の掲載を確認できません",
                            host_ids={"Manufacturer&Family": "44444444-4444-4444-4444-444444444444"})

    def test_old_release_for_another_vendor_does_not_count_as_a_model_listing(self):
        xml = self.catalog_with_component_data(
            '<requires><firmware compare="eq" version="DMI:OTHER">vendor-id</firmware></requires>')
        xml = xml.replace(b'release version="131072"', b'release version="65536"')
        self.exercise_check(None, xml=xml, expected_output="この機種の掲載を確認できません")
        with patch.object(self, "bios", dict(self.bios, VendorIds=[])):
            self.exercise_check(None, xml=xml, expected_hold="機種の必須条件を確認できません")

    def test_alternate_branch_counts_as_a_model_listing_without_an_update(self):
        xml = self.catalog_with_component_data("<branch>alternate</branch>")
        self.exercise_check(None, xml=xml, expected_output=(
            "この機種は掲載されています。 このBIOSで利用できる新版はありません（現行ブランチ）"))

    def test_policy_excludes_only_a_cab_with_a_matching_signed_container_hash(self):
        xml = self.catalog_with_competitor("196608")
        self.exercise_check(self.published, xml=xml, policy=(None, {"b" * 64}))
        self.exercise_check(self.published, xml=xml, policy=(None, {"c" * 64}), expected_hold="上位版")

    def test_allows_lower_candidate_only_when_the_newer_sku_is_excluded(self):
        sku = "22222222-2222-2222-2222-222222222222"
        second_sku = "33333333-3333-3333-3333-333333333333"
        xml = self.catalog_with_competitor("196608", component_data=(
            f"<requires><hardware>{sku}|{second_sku}</hardware></requires>"))
        key = "Manufacturer&Family&ProductName&ProductSku"
        self.exercise_check(self.published, xml=xml, host_ids={key: "44444444-4444-4444-4444-444444444444"})
        self.exercise_check(self.published, xml=xml, host_ids={key: second_sku}, expected_hold="上位版")

    def test_allows_a_required_intermediate_version_and_ignores_older_entries(self):
        xml = self.catalog_with_competitor(
            "196608", component_data='<requires><firmware compare="ge" version="2.0"/></requires>')
        self.exercise_check(self.published, xml=xml)
        self.exercise_check(self.published, xml=self.catalog_with_competitor("65536"))

    def test_current_version_can_exclude_a_competitor_when_its_hardware_ids_are_unavailable(self):
        xml = self.catalog_with_competitor("196608", component_data=(
            '<requires><hardware>33333333-3333-3333-3333-333333333333</hardware>'
            '<firmware compare="ge" version="2.0"/></requires>'))
        self.exercise_check(self.published, xml=xml, host_ids={})

    def test_number_format_uses_the_numeric_value_of_hex_encoded_releases(self):
        first = self.signed_xml.replace(b'version="131072"', b'version="2"')
        root = ET.fromstring(first)
        releases = root.find("component/releases")
        competitor = ET.fromstring(ET.tostring(releases[0]))
        competitor.set("version", "0x3")
        competitor.find(".//checksum").text = "b" * 64
        releases.append(competitor)
        bios = dict(self.bios, Version="1", VersionFormat="number")
        release = dict(self.published, Version="2")
        with patch.object(self, "bios", bios):
            self.exercise_check(release, xml=ET.tostring(root), expected_hold="上位版")

    def exercise_apply(self, latest_xml, *, expected_error=None, secure_boot_before=b"\x01",
                       secure_boot_after=b"\x01", disk_support_after=4):
        verify_path = "/proc/self/fd/23"
        with TemporaryDirectory() as tmp:
            esp = Path(tmp) / "esp"
            esp.mkdir()
            variables = Path(tmp) / "efivars"
            variables.mkdir()
            secure_boot = variables / f"SecureBoot-{updater.EFI_GLOBAL}"
            secure_boot.write_bytes(struct.pack("<I", 7) + secure_boot_before)
            disk_support = variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}"
            disk_support.write_bytes(struct.pack("<IQ", 7, 4))
            bios = dict(self.bios, Flags=["updatable"])
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            cabinet = SimpleNamespace(fileno=lambda: 23)
            catalog = Mock(side_effect=[(list(ET.fromstring(xml)), "2.0.20")
                                        for xml in (self.signed_xml, latest_xml)])
            verify = Mock(return_value="FMP画像1件")
            send = Mock()
            marker = Path(tmp) / "marker"

            def approve(_prompt):
                if secure_boot_after is None:
                    secure_boot.unlink()
                else:
                    secure_boot.write_bytes(struct.pack("<I", 7) + secure_boot_after)
                if disk_support_after is None:
                    disk_support.unlink()
                else:
                    disk_support.write_bytes(struct.pack("<IQ", 7, disk_support_after))
                return "yes"

            with (redirect_stdout(io.StringIO()),
                  patch.object(sys, "argv", [SCRIPT.name, "--apply"]),
                  patch.object(sys.stdin, "isatty", return_value=True),
                  patch.object(sys.stdout, "isatty", return_value=True),
                  patch.object(updater, "fwupd_bindings", return_value=(
                      None, SimpleNamespace(Error=FixtureGLibError, Regex=FixtureRegex))),
                  patch.multiple(updater, ESRT=Path(tmp), DMI=Path(tmp), EFIVARS=variables, require_fwupdmgr=Mock(),
                                 read_settings=Mock(return_value=profile), support_profile=Mock(return_value=profile),
                                 inventory=Mock(return_value=(self.guid, bios, [bios])),
                                 stable_remote=Mock(return_value={"Id": "lvfs"}), rows=Mock(return_value=[]),
                                 admin_checksums=Mock(return_value=(None, set())), load_stable_catalog=catalog,
                                 candidate=Mock(return_value=self.published), marker_path=Mock(return_value=marker),
                                 mount_points=Mock(return_value={str(variables): ("0:1", "/", "efivarfs")}),
                                 find_esp=Mock(return_value=(esp, self.guid)), check_power=Mock(),
                                 open_cabinet=Mock(return_value=nullcontext(cabinet)),
                                 fetch_cab=Mock(return_value=verify_path), verify_cab=verify, send_once=send),
                  patch("builtins.input", side_effect=approve)):
                if expected_error:
                    with self.assertRaisesRegex(updater.Hold, expected_error):
                        updater.main()
                    send.assert_not_called()
                else:
                    updater.main()
                    self.assertEqual([call.args[0] for call in verify.call_args_list], [verify_path, verify_path])
                    send.assert_called_once_with(marker, bios, self.published, 23)
                self.assertEqual(catalog.call_count, 2)

    def test_apply_rechecks_the_signed_catalog_after_approval(self):
        self.exercise_apply(self.signed_xml)
        self.exercise_apply(self.catalog_with_competitor("196608"), expected_error="上位版")
        xml = self.catalog_with_component_data('<requires><firmware compare="lt" version="1.0"/></requires>')
        self.exercise_apply(xml, expected_error="必須条件")

    def test_apply_rechecks_the_signed_vendor_id_after_approval(self):
        xml = self.catalog_with_component_data(
            '<requires><firmware compare="eq" version="DMI:OTHER">vendor-id</firmware></requires>')
        self.exercise_apply(xml, expected_error="機種条件")

    def test_apply_rechecks_recommends_and_suggests_after_approval(self):
        for kind in ("recommends", "suggests"):
            with self.subTest(kind=kind):
                xml = self.catalog_with_component_data(
                    f'<{kind}><firmware compare="lt" version="1.0"/></{kind}>')
                self.exercise_apply(xml, expected_error="必須条件")

    def test_apply_rechecks_update_protocol_and_version_format_after_approval(self):
        for key, value in (("LVFS::UpdateProtocol", "org.usb.dfu"), ("LVFS::VersionFormat", "quad")):
            with self.subTest(key=key):
                xml = self.catalog_with_component_data(f'<custom><value key="{key}">{value}</value></custom>')
                self.exercise_apply(xml, expected_error="配布条件")

    def test_apply_holds_when_secure_boot_disappears_or_changes_after_approval(self):
        for state in (None, b"\x00"):
            with self.subTest(secure_boot=state):
                self.exercise_apply(self.signed_xml, secure_boot_after=state, expected_error="Secure[ ]?Boot")

    def test_apply_rechecks_declared_disk_delivery_with_secure_boot_off(self):
        for supported in (4, 0, None):
            with self.subTest(supported=supported):
                self.exercise_apply(self.signed_xml, secure_boot_before=b"\x00", secure_boot_after=b"\x00",
                                    disk_support_after=supported, expected_error=None if supported else "OsIndicationsSupported")


class CatalogSizeTest(unittest.TestCase):
    def release(self, *, size="", artifact_size="", other=""):
        return ET.fromstring(f"""<release>{size}<artifacts><artifact type="binary">
          <filename>bios.cab</filename><checksum type="sha256">{"a" * 64}</checksum>{artifact_size}
          </artifact>{other}</artifacts></release>""")

    def test_signed_download_size_can_be_stored_at_either_level(self):
        size = '<size type="download">17</size>'
        for release in (self.release(size=size), self.release(artifact_size=size),
                        self.release(size=size, artifact_size=size)):
            with self.subTest(xml=ET.tostring(release)):
                self.assertEqual(updater.catalog_download_size(release), 17)

    def test_signed_download_sizes_must_agree(self):
        release = self.release(size='<size type="download">17</size>',
                               artifact_size='<size type="download">23</size>')
        with self.assertRaisesRegex(updater.Hold, "受信サイズ"):
            updater.catalog_download_size(release)

    def test_release_size_for_multiple_binary_artifacts_is_ambiguous(self):
        release = self.release(size='<size type="download">17</size>',
                               other='<artifact type="binary"><filename>another.cab</filename></artifact>')
        with self.assertRaisesRegex(updater.Hold, "受信サイズ"):
            updater.catalog_download_size(release)

    def test_later_artifacts_for_the_same_cab_contribute_their_signed_sizes(self):
        other = (f'<artifact type="binary"><filename>bios.cab</filename><checksum type="sha256">{"a" * 64}</checksum>'
                 '<size type="download">17</size></artifact>')
        size = '<size type="download">17</size>'
        for release in (self.release(other=other), self.release(artifact_size=size, other=other),
                        self.release(size=size, other=other)):
            with self.subTest(xml=ET.tostring(release)):
                self.assertEqual(updater.catalog_download_size(release), 17)
        conflict = self.release(artifact_size='<size type="download">23</size>', other=other)
        with self.assertRaisesRegex(updater.Hold, "受信サイズ"):
            updater.catalog_download_size(conflict)

    def test_size_for_a_different_cab_is_not_used_even_when_its_name_matches(self):
        other = (f'<artifact type="binary"><filename>bios.cab</filename><checksum type="sha256">{"b" * 64}</checksum>'
                 '<size type="download">23</size></artifact>')
        self.assertIsNone(updater.catalog_download_size(self.release(other=other)))
        size = '<size type="download">17</size>'
        self.assertEqual(updater.catalog_download_size(self.release(artifact_size=size, other=other)), 17)

    def test_release_size_requires_the_legacy_reference_to_match_the_binary_artifact(self):
        size = '<size type="download">17</size>'
        for filename, digest in (("other.cab", "a" * 64), ("bios.cab", "b" * 64)):
            with self.subTest(filename=filename, digest=digest):
                release = self.release(size=size + (
                    f'<checksum target="container" filename="{filename}" type="sha256">{digest}</checksum>'))
                with self.assertRaisesRegex(updater.Hold, "受信サイズ"):
                    updater.catalog_download_size(release)
        legacy = ET.fromstring(f"<release>{size}</release>")
        self.assertEqual(updater.catalog_download_size(legacy), 17)


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
                  patch.object(updater, "read_esrt", return_value=str(guid)),
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
                        updater.fwupd_efi_state()

    def test_cleared_registration_with_valid_device_path_is_not_pending(self):
        guid = CapsuleScopeTest.guid
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            entry = Path(tmp) / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}"
            entry.write_bytes(self.fwupd_variable(0, guid))
            self.assertEqual(updater.fwupd_efi_state(), ([], False))

    def test_status_counts_the_reservation_when_a_bootloader_capability_is_present(self):
        guid = CapsuleScopeTest.guid
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            variables = Path(tmp)
            flag = variables / f"BootloaderSupportsFwupd-{updater.FWUPDATE_GUID}"
            (variables / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}").write_bytes(self.fwupd_variable(1, guid))
            for capability in (0, 1):
                with self.subTest(capability=capability), redirect_stdout(io.StringIO()) as output:
                    flag.write_bytes(struct.pack("<IB", 7, capability))
                    updater.show_efi_variables(str(guid))
                    self.assertIn("実行待ち登録1件（BIOS対象1件）", output.getvalue())

    def test_malformed_bootloader_capability_is_held(self):
        with TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)):
            flag = Path(tmp) / f"BootloaderSupportsFwupd-{updater.FWUPDATE_GUID}"
            for payload in (b"", b"\x02", b"\x01\x00"):
                with self.subTest(payload=payload):
                    flag.write_bytes(struct.pack("<I", 7) + payload)
                    with self.assertRaisesRegex(updater.Hold, "BootloaderSupportsFwupd"):
                        updater.fwupd_efi_state()

    def test_status_prints_delivery_bit_even_when_esp_cannot_be_resolved(self):
        with (patch.object(updater, "mount_points", return_value={}),
              patch.object(updater, "require_efivarfs"),
              patch.object(updater, "fwupd_efi_state", return_value=([], False)),
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
                  patch.object(updater, "read_esrt", return_value=str(CapsuleScopeTest.guid)),
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
                  patch.object(updater, "read_esrt", return_value=str(CapsuleScopeTest.guid)),
                  patch.object(updater, "inventory", return_value=(str(CapsuleScopeTest.guid), bios, [bios])),
                  patch.object(updater, "DMI", Path(tmp)),
                  patch.object(updater, "show_reservations"),
                  patch.object(updater, "marker_path", return_value=marker),
                  patch.object(updater, "rows", side_effect=updater.Error("history unavailable")),
                  self.assertRaisesRegex(updater.Error, "history unavailable")):
                updater.main()
        self.assertIn("この起動で更新を依頼しています", output.getvalue())

    def test_status_keeps_the_esrt_guid_if_fwupd_device_enumeration_fails(self):
        guid = CapsuleScopeTest.guid
        with TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output:
            base = Path(tmp)
            entries = base / "esrt"
            entry = entries / "entry0"
            entry.mkdir(parents=True)
            (entry / "fw_type").write_text("1\n", encoding="ascii")
            (entry / "fw_class").write_text(str(guid), encoding="ascii")
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"fwupd-{guid}-0-{updater.FWUPDATE_GUID}").write_bytes(
                self.fwupd_variable(1, guid))
            with (patch.object(updater, "ESRT", entries),
                  patch.object(updater, "EFIVARS", variables),
                  patch.object(updater, "require_fwupdmgr"),
                  patch.object(updater, "mount_points", return_value={str(variables): ("0:1", "/", "efivarfs")}),
                  patch.object(updater, "find_esp", return_value=(base, str(BootEntryTest.esp))),
                  patch.object(updater, "marker_path", return_value=base / "marker"),
                  patch.object(updater, "rows", side_effect=updater.Error("get-devices unavailable")),
                  self.assertRaisesRegex(updater.Error, "get-devices unavailable")):
                updater.show_status()
        self.assertIn("BIOS対象1件", output.getvalue())

    def test_status_preserves_each_readable_delivery_location(self):
        locations = (updater.STANDARD_CAPSULE_DIR, updater.DELL_RECOVERY_FILE)
        for present, unreadable in (locations, locations[::-1]):
            with self.subTest(present=present):
                def inspect(_esp, path, *, directory):
                    if path == unreadable:
                        raise PermissionError("unreadable")
                    return True

                with (patch.object(updater, "mount_points", return_value={}),
                      patch.object(updater, "require_efivarfs"),
                      patch.object(updater, "show_efi_variables"),
                      patch.object(updater, "find_esp", return_value=(Path("/boot/efi"), str(BootEntryTest.esp))),
                      patch.object(updater, "esp_has_entry", side_effect=inspect),
                      redirect_stdout(io.StringIO()) as output):
                    updater.show_reservations(str(CapsuleScopeTest.guid))
                lines = output.getvalue().splitlines()
                self.assertTrue(any(present in line and "内容未確認" in line for line in lines), lines)
                self.assertTrue(any(unreadable in line and "確認不能" in line for line in lines), lines)


class ReadinessTest(unittest.TestCase):
    def check_secure_boot_readiness(self, base, profile):
        esp, efivars = base / "esp", base / "efivars"
        bios = {"DeviceId": "b" * 40, "Flags": ["updatable"]}
        with (patch.object(updater, "EFIVARS", efivars),
              patch.object(updater, "mount_points", return_value={str(efivars): ("0:1", "/", "efivarfs")}),
              patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
              patch.object(updater, "check_power")):
            return updater.check_ready(bios, [bios], [], profile)

    def test_secure_boot_requires_a_verified_shim_on_esp_or_in_the_fwupd_package(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 1))
            assets = base / "package"
            assets.mkdir()
            (assets / "fwupdx64.efi.signed").write_bytes(b"verified loader")
            shim = b"verified shim"
            profile = {"secure_boot": {
                "delivery": "shim",
                "esp_vendor_dir": "ubuntu",
                "efi_app_dir": str(assets),
                "fwupd_efi_sha256": hashlib.sha256(b"verified loader").hexdigest(),
                "shim_sha256": [hashlib.sha256(shim).hexdigest()],
                "shim_copy_sbat_sha256": None,
            }}
            with self.assertRaisesRegex(updater.Hold, "shim"):
                self.check_secure_boot_readiness(base, profile)

            packaged = assets / "shimx64.efi.signed"
            packaged.write_bytes(shim)
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")
            sbat = struct.pack("<I", 7) + b"changed SBAT policy"
            (variables / "SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23").write_bytes(sbat)
            with self.assertRaisesRegex(updater.Hold, "SBAT"):
                self.check_secure_boot_readiness(base, profile)

            installed = base / "esp" / "EFI" / "ubuntu" / "shimx64.efi"
            installed.parent.mkdir(parents=True)
            installed.write_bytes(shim)
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")
            packaged.write_bytes(b"unexpected packaged shim")
            with self.assertRaisesRegex(updater.Hold, "shim"):
                self.check_secure_boot_readiness(base, profile)
            packaged.unlink()
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

    def test_secure_boot_disk_delivery_profile_requires_efi_capability(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 1))
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            with self.assertRaisesRegex(updater.Hold, "OsIndicationsSupported"):
                self.check_secure_boot_readiness(base, profile)
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

    def test_readiness_requires_a_confirmed_secure_boot_state(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            with self.assertRaisesRegex(updater.Hold, "Secure Boot"):
                self.check_secure_boot_readiness(base, {})
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            self.assertEqual(self.check_secure_boot_readiness(base, {})[0], base / "esp")

    def test_bootloader_capability_requires_a_verified_delivery_route(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"BootloaderSupportsFwupd-{updater.FWUPDATE_GUID}").write_bytes(struct.pack("<IB", 7, 1))
            with self.assertRaisesRegex(updater.Hold, "配送方式"):
                self.check_secure_boot_readiness(base, {})
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            with self.assertRaisesRegex(updater.Hold, "OsIndicationsSupported"):
                self.check_secure_boot_readiness(base, profile)
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

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
                  patch.object(updater, "fwupd_efi_state", return_value=([], False)),
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
        with io.BytesIO() as cab, patch.object(updater, "build_opener") as build:
            with self.assertRaises(updater.Error):
                updater.fetch_cab(release, remote, cab, {})
            build.return_value.open.assert_not_called()
            self.assertEqual(cab.getvalue(), b"")

    def test_download_enforces_the_actual_byte_count_without_content_length(self):
        data = b"0123456789"
        release = {"Locations": ["https://cdn.fwupd.org/downloads/test.cab"],
                   "Checksum": [hashlib.sha256(data).hexdigest()]}
        remote = {"MetadataUri": "https://cdn.fwupd.org/downloads/firmware.xml.zst"}
        with (io.BytesIO() as cab,
              patch.object(updater, "CAB_DOWNLOAD_LIMIT", 8),
              patch.object(updater, "build_opener") as build):
            build.return_value.open.return_value = io.BytesIO(data)
            with self.assertRaisesRegex(updater.Hold, "上限"):
                updater.fetch_cab(release, remote, cab, {})
            self.assertLessEqual(len(cab.getvalue()), 8)

    def test_download_honors_the_signed_size_without_an_http_length(self):
        url = "https://cdn.fwupd.org/downloads/test.cab"
        remote = {"MetadataUri": "https://cdn.fwupd.org/downloads/firmware.xml.zst"}
        release = {"Locations": [url], "Checksum": [hashlib.sha256(b"01234567").hexdigest()]}
        for data, expected_error in ((b"0123456", "一致"), (b"012345678", "上限")):
            with (self.subTest(data=data), io.BytesIO() as cab,
                  patch.object(updater, "build_opener") as build):
                build.return_value.open.return_value = io.BytesIO(data)
                with self.assertRaisesRegex(updater.Hold, expected_error):
                    updater.fetch_cab(release, remote, cab, {}, download_size=8)
                self.assertLessEqual(len(cab.getvalue()), 8)

    def test_redirect_closes_the_intermediate_response_without_reading_its_body(self):
        origin = "https://cdn.fwupd.org/downloads/"
        initial, final = origin + "initial.cab", origin + "final.cab"
        supported_statuses = (301, 302, 303, 307, 308)
        for code in supported_statuses:
            with self.subTest(code=code):
                body = io.BytesIO(b"payload outside the CAB transfer")
                requests = []

                class FixtureHttps(HTTPSHandler):
                    def https_open(self, request):
                        requests.append(request.full_url)
                        headers = Message()
                        if request.full_url == initial:
                            headers["Location"] = "/downloads/final.cab"
                            response = addinfourl(body, headers, initial, code)
                        else:
                            response = addinfourl(io.BytesIO(b"test CAB"), headers, final, 200)
                        response.msg = "test response"
                        return response

                opener = build_opener(ProxyHandler({}), FixtureHttps(),
                                      updater.CabRedirectHandler(updater.cab_bases({})))
                with patch.object(body, "read", wraps=body.read) as read:
                    with opener.open(Request(initial), timeout=60) as response:
                        self.assertEqual(response.read(), b"test CAB")
                    self.assertTrue(body.closed)
                    read.assert_not_called()
                self.assertEqual(requests, [initial, final])

    def test_retry_cannot_use_bytes_already_budgeted_for_a_failed_location(self):
        class Interrupted(io.BytesIO):
            def read(self, size):
                if self.tell():
                    raise ConnectionResetError("test interruption")
                return super().read(size)

        mib = 1024 * 1024
        base = "https://cdn.fwupd.org/downloads/"
        remote = {"MetadataUri": base + "firmware.xml.zst"}
        for data in (b"12345678", b"123456789"):
            with (self.subTest(size=len(data)), io.BytesIO() as cab,
                  patch.object(updater, "CAB_DOWNLOAD_LIMIT", 2 * mib + 8),
                  patch.object(updater, "build_opener") as build,
                  patch.object(updater, "seal_cabinet", return_value="sealed fixture") as seal):
                build.return_value.open.side_effect = [Interrupted(b"?" * mib), io.BytesIO(data)]
                release = {"Locations": [base + "first.cab", base + "second.cab"],
                           "Checksum": [hashlib.sha256(data).hexdigest()]}
                if len(data) == 8:
                    self.assertEqual(updater.fetch_cab(release, remote, cab, {}), "sealed fixture")
                    self.assertEqual(cab.getvalue(), data)
                else:
                    with self.assertRaisesRegex(updater.Hold, "上限"):
                        updater.fetch_cab(release, remote, cab, {})
                    seal.assert_not_called()


class CabinetHandoffTest(unittest.TestCase):
    def test_install_uses_inherited_descriptor_and_keeps_standard_dialog(self):
        bios = {"DeviceId": "b" * 40}
        release = {"Version": "2.0"}
        fd = 23
        with (TemporaryDirectory() as tmp,
              patch.object(updater.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True),
              patch.object(updater.subprocess, "Popen") as popen):
            popen.return_value.wait.return_value = 0
            updater.send_once(Path(tmp) / "marker", bios, release, fd)
            popen.assert_called_once_with([updater.FWUPDMGR, "--no-reboot-check", "local-install",
                                           f"/proc/self/fd/{fd}", bios["DeviceId"]], pass_fds=(fd,))

    def test_digest_check_reads_the_bytes_after_sealing(self):
        data = b"approved CAB"
        release = {"Checksum": [hashlib.sha256(data).hexdigest()]}
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "cab"
            with (path.open("w+b") as cab,
                  patch.object(updater, "cabinet_path", return_value=str(path))):
                cab.write(data)

                def finish_sealing(*_args):
                    cab.seek(0)
                    cab.write(b"changed CAB!")
                    cab.flush()

                fake_fcntl = SimpleNamespace(F_SEAL_WRITE=1, F_SEAL_SHRINK=2, F_SEAL_GROW=4,
                                             F_SEAL_SEAL=8, F_ADD_SEALS=16, fcntl=finish_sealing)
                with (patch.dict(sys.modules, {"fcntl": fake_fcntl}),
                      self.assertRaisesRegex(updater.Hold, "ハッシュ")):
                    updater.seal_cabinet(cab, release)

    @unittest.skipUnless(hasattr(os, "memfd_create"), "requires Linux memfd and procfs")
    def test_verified_archive_cannot_be_rewritten_and_child_reads_the_same_bytes(self):
        data = b"captured CAB bytes"
        release = {"Locations": ["https://cdn.fwupd.org/downloads/test.cab"],
                   "Checksum": [hashlib.sha256(data).hexdigest()]}
        remote = {"MetadataUri": "https://cdn.fwupd.org/downloads/firmware.xml.zst"}
        with updater.open_cabinet() as cab, patch.object(updater, "build_opener") as build:
            build.return_value.open.return_value = io.BytesIO(data)
            path = updater.fetch_cab(release, remote, cab, {}, download_size=len(data))
            with self.assertRaises(PermissionError):
                os.pwrite(cab.fileno(), b"changed", 0)
            with self.assertRaises(PermissionError):
                os.ftruncate(cab.fileno(), 0)
            child = subprocess.run([sys.executable, "-c",
                                    "from pathlib import Path; import sys; sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())",
                                    path], pass_fds=(cab.fileno(),), capture_output=True, check=True)
            self.assertEqual(child.stdout, data)
