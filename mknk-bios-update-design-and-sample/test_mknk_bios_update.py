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
import shutil
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
        profile = {"fmp": {"image_type_id": guid, "image_index": 1, "hardware_instance": 0}}
        payload = self.single_image()
        for fmt, raw, version in (("pair", "131072", "2.0"), ("bcd", "0x03800290", "3.80.2.90")):
            device = {"DeviceId": "b" * 40, "VersionFormat": fmt}
            candidate = {"Version": version, "AppstreamId": "example.bios"}
            detail = {"AppstreamId": "example.bios", "Version": raw, "Flags": ["trusted-payload"]}
            with (self.subTest(fmt=fmt),
                  patch.object(updater, "fwupd_query", return_value=[{"Guid": [guid], "Releases": [detail]}]),
                  patch.object(updater, "read_cab_files", side_effect=[
                      {"bios.metainfo.xml": manifest.replace(b"131072", raw.encode())}, {"new.bin": payload}])):
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
    bios = {"DeviceId": "b" * 40, "Version": "1.0", "VersionFormat": "pair", "Guid": [guid],
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
                       device_before_refresh=None, other_devices=(), runtime_policy=None):
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
            return self.guid, device, [device, *other_devices]

        client = SimpleNamespace(update_metadata_bytes=update, get_daemon_version=lambda: daemon_version)
        fwupd = SimpleNamespace(Client=SimpleNamespace(new=lambda: client),
                                Error=SimpleNamespace(NOTHING_TO_DO=19))
        glib = SimpleNamespace(Bytes=SimpleNamespace(new=bytes), Error=FixtureGLibError, Regex=FixtureRegex,
                               Variant=lambda kind, value: (kind, value), VariantType=SimpleNamespace(new=str))
        imports = {"gi": SimpleNamespace(require_version=lambda *_args: None),
                   "gi.repository": SimpleNamespace(Fwupd=fwupd, GLib=glib)}
        admin_patch = patch.object(updater, "admin_checksums", return_value=policy)
        help_patch = nullcontext()
        policy_calls = []
        if runtime_policy is not None:
            running_version, blocked, client_help = runtime_policy

            def call(destination, path, interface, method, params, reply_type, *_args):
                policy_calls.append(method)
                if method == "GetNameOwner":
                    self.assertEqual(params, ("(s)", (updater.FWUPD_ID,)))
                    return SimpleNamespace(unpack=lambda: (":1.7",))
                self.assertEqual((destination, path), (":1.7", "/"))
                if method == "Get":
                    self.assertEqual(params, ("(ss)", (updater.FWUPD_ID, "DaemonVersion")))
                    return SimpleNamespace(unpack=lambda: (running_version,))
                self.assertEqual((interface, method, params, reply_type),
                                 (updater.FWUPD_ID, "GetBlockedFirmware", None, "(as)"))
                if isinstance(blocked, Exception):
                    raise blocked
                return SimpleNamespace(unpack=lambda: (blocked,))

            bus = SimpleNamespace(call_sync=call)
            imports["gi.repository"].Gio = SimpleNamespace(
                bus_get_sync=lambda *_args: bus, BusType=SimpleNamespace(SYSTEM=0),
                DBusCallFlags=SimpleNamespace(NO_AUTO_START=1))
            admin_patch = nullcontext()
            help_patch = patch.object(updater.subprocess, "run", return_value=SimpleNamespace(stdout=client_help))
        with (TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()) as output,
              patch.dict(sys.modules, imports),
              patch.object(sys, "argv", [SCRIPT.name, "--check"]),
              patch.object(updater.os.path, "isfile", return_value=True),
              patch.object(updater, "DMI", Path(tmp)),
              patch.object(updater, "ESRT", Path(tmp)),
              patch.object(updater, "read_settings", return_value={}),
              patch.object(updater, "stable_remote", side_effect=[remote, remote, active_remote]),
              patch.object(updater, "command", return_value=json.dumps(host_ids)) as command,
              admin_patch as admin, help_patch as help_command,
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
                if expected_output:
                    self.assertIn(expected_output, output.getvalue())
        if host_ids is None:
            command.assert_not_called()
        else:
            command.assert_called_once_with(["hwids"])
        if approval_required:
            admin.assert_called_once_with(active_remote)
        if runtime_policy is not None:
            help_command.assert_not_called()
            return policy_calls
        self.assertCountEqual(requests, [self.signature_uri, self.metadata_uri])
        self.assertEqual(daemon_calls, [("lvfs", signed, signature)])

    def test_check_uses_only_the_approved_lvfs_catalog(self):
        self.exercise_check(self.published)

    def test_new_cli_obeys_old_daemon_block_list_for_a_newer_release(self):
        calls = self.exercise_check(self.published, xml=self.catalog_with_competitor("196608"),
                                    expected_output="新版 3.0　明示ブロック",
                                    runtime_policy=("2.0.20", ["B" * 64], ""))
        self.assertIn("GetBlockedFirmware", calls)

    def test_old_cli_skips_block_list_removed_from_new_daemon(self):
        calls = self.exercise_check(self.published, runtime_policy=(
            "2.1.1", FixtureGLibError("Unknown method"), "  get-blocked-firmware   Show blocked firmware"))
        self.assertIn("Get", calls)
        self.assertNotIn("GetBlockedFirmware", calls)

    def test_missing_block_list_on_old_daemon_holds_the_candidate(self):
        calls = self.exercise_check(self.published, expected_hold="管理者.*確認できません",
                                    runtime_policy=("2.0.20", FixtureGLibError("Unavailable"), ""))
        self.assertIn("GetBlockedFirmware", calls)

    def test_check_displays_community_support_status(self):
        self.exercise_check(dict(self.published, Flags=["is-community"]), expected_output="コミュニティ提供")

    def test_reused_remote_id_does_not_authorize_an_unpublished_cab(self):
        self.exercise_check(dict(self.published, Checksum=["b" * 64]), expected_hold="署名済み")

    def test_container_hash_from_a_different_guid_does_not_prove_catalog_membership(self):
        foreign = self.signed_xml.replace(self.guid.encode(), b"00000000-0000-0000-0000-000000000001")
        self.exercise_check(self.published, xml=foreign, expected_hold="署名済み")

    def test_signature_rejection_stops_candidate_display(self):
        self.exercise_check(self.published, metadata_result=9, expected_hold="署名")

    def test_check_shows_local_bios_even_when_catalog_verification_fails(self):
        self.exercise_check(self.published, metadata_result=9, expected_hold="署名",
                            expected_output="現在のBIOS 1.0")

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

    def test_a_unique_guid_requirement_uses_the_bios_version(self):
        xml = self.catalog_with_component_data(
            f'<requires><firmware compare="ge" version="1.0">{self.guid}</firmware></requires>')
        self.exercise_check(self.published, xml=xml)
        self.exercise_check(self.published, xml=xml.replace(b'version="1.0"', b'version="1.1"'),
                            expected_hold="必須条件")
        self.exercise_check(self.published, xml=xml, expected_hold="条件を確認できません",
                            other_devices=[dict(self.bios, DeviceId="c" * 40)])

    def test_firmware_guid_presence_does_not_require_a_unique_versioned_device(self):
        peer_guid = "33333333-3333-3333-3333-333333333333"
        xml = self.catalog_with_component_data(
            f'<requires><firmware>{peer_guid}</firmware></requires>')
        peer = {"DeviceId": "c" * 40, "Guid": [peer_guid]}
        self.exercise_check(self.published, xml=xml, other_devices=[peer, dict(peer, DeviceId="d" * 40)])
        self.exercise_check(self.published, xml=xml, expected_hold="必須条件を満たしません")
        self.exercise_check(self.published, xml=xml, other_devices=[dict(peer, Guid=None)],
                            expected_hold="必須条件を確認できません")

    def test_version_check_required_demands_a_component_hard_requirement(self):
        hard = '<requires><firmware compare="ge" version="1.0"/></requires>'
        soft = hard.replace("requires", "recommends")
        release_level = ET.fromstring(self.signed_xml)
        release_level.find("component/releases/release").append(ET.fromstring(hard))
        with patch.object(self, "bios", dict(self.bios, Flags=["version-check-required"])):
            for xml in (self.signed_xml, self.catalog_with_component_data(soft), ET.tostring(release_level)):
                with self.subTest(xml=xml):
                    self.exercise_check(self.published, xml=xml, expected_hold="必須の版条件")
            self.exercise_check(self.published, xml=self.catalog_with_component_data(hard))

    def test_names_known_client_features_that_the_sample_does_not_provide(self):
        xml = self.catalog_with_component_data('<requires><client>requests|switch-branch</client></requires>')
        self.exercise_check(self.published, xml=xml, expected_hold=r"switch-branch.*対応")
        self.exercise_check(None, xml=xml, expected_hold=r"switch-branch.*対応")
        self.exercise_check(self.published, xml=xml.replace(b"switch-branch", b"made-up"),
                            expected_hold="必須条件")

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

    def test_fwupd_id_glob_uses_the_first_matching_branch_or_final_fallback(self):
        for version, accepted in (("2.0.20", True),
                                  ("2.0.*=2.0.20|2.*=2.99.0|2.99.0", True),
                                  ("2.0.*=2.0.21|2.*=2.0.20|2.0.20", False),
                                  ("1.9.*=1.9.7|2.0.20", True),
                                  ("1.9.*=1.9.7|2.0.21", False),
                                  ("1.9.*=1.9.7", True)):
            with self.subTest(version=version):
                xml = self.catalog_with_component_data(
                    '<requires><client>id-requirement-glob</client>'
                    f'<id compare="ge" version="{version}">org.freedesktop.fwupd</id></requires>')
                self.exercise_check(self.published, xml=xml, expected_hold=None if accepted else "必須条件")

    def test_fwupd_id_glob_holds_unverified_daemon_and_malformed_expressions(self):
        xml = self.catalog_with_component_data(
            '<requires><client>id-requirement-glob</client>'
            '<id compare="ge" version="2.0.*=2.0.20|2.0.20">org.freedesktop.fwupd</id></requires>')
        self.exercise_check(self.published, xml=xml, daemon_version="2.0.19", expected_hold="必須条件")
        for bad in (b"2.0.*=", b"2.0.*=2.0.20|", b"2.0.*=2.0.20||2.0.20", b"2.0.*=2.0.20|1.9.*==1.9.7",
                    b"2.0.20|2.0.21", b"[2].0.*=2.0.20"):
            with self.subTest(version=bad):
                self.exercise_check(self.published, xml=xml.replace(b"2.0.*=2.0.20|2.0.20", bad),
                                    expected_hold="必須条件")
        self.exercise_check(self.published, xml=xml.replace(b"id-requirement-glob", b"unknown-feature"),
                            expected_hold="必須条件")
        self.exercise_check(self.published, xml=xml.replace(b"<client>id-requirement-glob</client>", b""),
                            expected_hold="必須条件")

    def test_fwupd_daemon_capability_does_not_require_a_gui_feature_flag(self):
        xml = self.catalog_with_component_data(
            '<requires><client>id-requirement-glob</client>'
            '<id compare="ge" version="2.0.?0=2.0.20|2.9.0">org.freedesktop.fwupd</id></requires>')
        result = updater.require_catalog_release(ET.fromstring(xml), self.bios, [self.bios], self.guid, self.published,
                                                 {}, daemon_version="2.0.20", client_features=(),
                                                 policy=(None, frozenset()))
        self.assertEqual(result.hashes, {"sha256": "a" * 64})

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

    def test_catalog_accepts_the_bcd_integer_version_of_the_selected_cab(self):
        xml = self.signed_xml.replace(b'version="131072"', b'version="0x03800290"')
        with patch.object(self, "bios", dict(self.bios, Version="3.70.2.90", VersionFormat="bcd")):
            self.exercise_check(dict(self.published, Version="3.80.2.90"), xml=xml)

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

    def catalog_with_cab_alias(self):
        root = ET.fromstring(self.signed_xml)
        artifacts = root.find("component/releases/release/artifacts")
        alias = ET.fromstring(ET.tostring(artifacts[0]))
        ET.SubElement(alias, "checksum", type="sha512").text = "e" * 128
        artifacts.append(alias)
        return ET.tostring(root)

    def test_signed_alias_of_selected_cab_is_enough_to_block_it(self):
        xml = self.catalog_with_cab_alias()
        self.exercise_check(self.published, xml=xml, policy=(None, {"e" * 128}), expected_hold="明示ブロック")
        self.exercise_check(self.published, xml=xml, policy=({"e" * 128}, set()), approval_required=True)

    def test_an_additional_index_digest_can_block_but_cannot_approve_the_cab(self):
        release = dict(self.published, Checksum=["a" * 64, "e" * 128])
        self.exercise_check(release, policy=(None, {"e" * 128}), expected_hold="明示ブロック")
        self.exercise_check(release, policy=({"e" * 128}, set()), approval_required=True, expected_hold="承認一覧")

    def test_index_and_catalog_can_identify_the_cab_with_either_strong_hash(self):
        xml = self.signed_xml.replace(b'a' * 64, b'e' * 128).replace(b"sha256", b"sha512")
        self.exercise_check(dict(self.published, Checksum=["a" * 64, "e" * 128]), xml=xml)

    def catalog_with_linked_release_records(self):
        root = ET.fromstring(self.signed_xml)
        releases = root.find("component/releases")
        bridge = releases[0].find(".//artifact")
        ET.SubElement(bridge, "checksum", type="sha512").text = "e" * 128
        alias = ET.fromstring(ET.tostring(releases[0]))
        alias.find(".//artifact").remove(alias.find(".//checksum[@type='sha256']"))
        releases.append(alias)
        return root, releases

    def test_same_release_records_link_through_a_signed_hash_using_either_order(self):
        for separate_components in (False, True):
            with self.subTest(separate_components=separate_components):
                root, releases = self.catalog_with_linked_release_records()
                siblings = releases
                if separate_components:
                    component = ET.fromstring(ET.tostring(root[0]))
                    component.find("releases").remove(component.find("releases/release"))
                    releases.remove(releases[1])
                    root.append(component)
                    siblings = root
                self.exercise_check(self.published, xml=ET.tostring(root))
                siblings[:] = list(reversed(siblings))
                self.exercise_check(self.published, xml=ET.tostring(root))

    def test_linked_release_records_must_agree_on_the_cab(self):
        root, releases = self.catalog_with_linked_release_records()
        ET.SubElement(releases[1].find(".//artifact"), "checksum", type="sha256").text = "b" * 64
        self.exercise_check(self.published, xml=ET.tostring(root), expected_hold="同じ方式で異なる")

    def test_linked_release_records_must_agree_on_the_cab_size(self):
        root, releases = self.catalog_with_linked_release_records()
        for entry, size in zip(releases, ("100", "101")):
            ET.SubElement(entry, "size", type="download").text = size
        self.exercise_check(self.published, xml=ET.tostring(root), expected_hold="受信サイズが一致しません")

    def test_linked_release_records_cannot_hide_an_unmet_requirement(self):
        root, releases = self.catalog_with_linked_release_records()
        releases[1].append(ET.fromstring('<requires><firmware compare="ge" version="2.0"/></requires>'))
        self.exercise_check(self.published, xml=ET.tostring(root), expected_hold="必須条件を満たしません")

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

    def test_check_explains_the_known_policy_reason_for_an_unavailable_newer_version(self):
        for policy, reason in (((None, {"a" * 64}), "明示ブロック"), ((set(), set()), "承認一覧")):
            with self.subTest(reason=reason):
                self.exercise_check(None, policy=policy, approval_required=policy[0] is not None,
                                    expected_output=f"新版 2.0　{reason}")

    def test_check_explains_the_known_intermediate_version_when_no_candidate_exists(self):
        xml = self.catalog_with_component_data('<requires><firmware compare="ge" version="1.5"/></requires>')
        self.exercise_check(None, xml=xml, expected_output="新版 2.0　前提版 1.5")

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

    def test_not_hardware_requires_real_chids_to_allow_or_exclude_a_model(self):
        excluded = "33333333-3333-3333-3333-333333333333"
        other = "44444444-4444-4444-4444-444444444444"
        requirement = f"<requires><not_hardware>{excluded}</not_hardware></requires>"
        xml = self.catalog_with_component_data(requirement)
        host_ids = {"Manufacturer&Family": other, "ProductSku": excluded}
        self.exercise_check(self.published, xml=xml, host_ids=host_ids)
        self.exercise_check(self.published, xml=xml, host_ids={"Manufacturer&Family": excluded},
                            expected_hold="機種条件を満たしません")
        self.exercise_check(self.published, xml=xml, host_ids={"ProductSku": other},
                            expected_hold="必須条件を確認できません")
        self.exercise_check(self.published, xml=xml,
                            host_ids={"Manufacturer&Family": other, "Manufacturer&ProductName": "invalid"},
                            expected_hold="必須条件を確認できません")

    def test_not_hardware_excludes_a_newer_release_only_when_a_chid_matches(self):
        excluded = "33333333-3333-3333-3333-333333333333"
        xml = self.catalog_with_competitor(
            "196608", component_data=f"<requires><not_hardware>{excluded}</not_hardware></requires>")
        self.exercise_check(self.published, xml=xml, host_ids={"Manufacturer&Family": excluded})
        self.exercise_check(self.published, xml=xml, host_ids={}, expected_hold="上位版")
        self.exercise_check(self.published, xml=xml, expected_hold="上位版",
                            host_ids={"Manufacturer&Family": "44444444-4444-4444-4444-444444444444"})

    def test_allows_a_required_intermediate_version_and_ignores_older_entries(self):
        xml = self.catalog_with_competitor(
            "196608", component_data='<requires><firmware compare="ge" version="2.0"/></requires>')
        self.exercise_check(self.published, xml=xml, expected_output="新版 3.0　前提版 2.0")
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
                       secure_boot_after=b"\x01", disk_support_after=4, boot_order_after=3,
                       boot_order_during_authorization=None, policy=(None, frozenset()), policy_after=None,
                       initial_xml=None, initial_release=None, latest_release=None, cabinet_bytes=None,
                       expected_output=None, esp_options=("rw", "rw")):
        verify_path = "/proc/self/fd/23"
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            esp = base / "esp"
            esp.mkdir()
            variables = Path(tmp) / "efivars"
            variables.mkdir()
            secure_boot = variables / f"SecureBoot-{updater.EFI_GLOBAL}"
            secure_boot.write_bytes(struct.pack("<I", 7) + secure_boot_before)
            disk_support = variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}"
            disk_support.write_bytes(struct.pack("<IQ", 7, 4))
            BootEntryTest.disk_boot_target(variables, uuid.UUID(self.guid))
            bios = dict(self.bios, Flags=["updatable"])
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            cabinet = io.BytesIO(b"test CAB" if cabinet_bytes is None else cabinet_bytes)
            cabinet.fileno = lambda: 23
            catalog = Mock(side_effect=[(list(ET.fromstring(xml)), "2.0.20")
                                        for xml in (initial_xml or self.signed_xml, latest_xml)])
            verify = Mock(return_value="FMP画像1件")
            send = Mock(return_value=SimpleNamespace(wait=lambda: 0))
            marker = Path(tmp) / "marker"
            release = initial_release or self.published

            def approve(_prompt):
                if secure_boot_after is None:
                    secure_boot.unlink()
                else:
                    secure_boot.write_bytes(struct.pack("<I", 7) + secure_boot_after)
                if disk_support_after is None:
                    disk_support.unlink()
                else:
                    disk_support.write_bytes(struct.pack("<IQ", 7, disk_support_after))
                (variables / f"BootOrder-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IH", 7, boot_order_after))
                return "yes"

            def sudo(args, _purpose):
                if esp_options != ("rw", "rw"):
                    self.fail("A read-only ESP must stop preparation before the request marker")
                self.assertEqual(Path(args[-1]), marker)
                if args[0] == "/usr/bin/mkdir":
                    marker.mkdir()
                    if boot_order_during_authorization is not None:
                        (variables / f"BootOrder-{updater.EFI_GLOBAL}").write_bytes(
                            struct.pack("<IH", 7, boot_order_during_authorization))
                else:
                    self.assertEqual(args[0], "/usr/bin/rmdir")
                    marker.rmdir()
                return b""

            with (redirect_stdout(io.StringIO()) as output,
                  patch.object(sys, "argv", [SCRIPT.name, "--apply"]),
                  patch.object(sys.stdin, "isatty", return_value=True),
                  patch.object(sys.stdout, "isatty", return_value=True),
                  patch.object(updater, "fwupd_bindings", return_value=(
                      None, SimpleNamespace(Error=FixtureGLibError, Regex=FixtureRegex))),
                  patch.object(updater, "partition_geometry", return_value=updater.PartitionGeometry(1, 64, 4096)),
                  patch.object(updater.subprocess, "Popen", send),
                  patch.multiple(updater, ESRT=Path(tmp), DMI=Path(tmp), EFIVARS=variables, require_fwupdmgr=Mock(),
                                 read_settings=Mock(return_value=profile), support_profile=Mock(return_value=profile),
                                 inventory=Mock(return_value=(self.guid, bios, [bios])),
                                 stable_remote=Mock(return_value={"Id": "lvfs"}), rows=Mock(return_value=[]),
                                 admin_checksums=Mock(side_effect=[policy, policy if policy_after is None else policy_after]),
                                 load_stable_catalog=catalog,
                                 candidate=Mock(side_effect=[release, latest_release or release]),
                                 marker_path=Mock(return_value=marker), sudo_command=sudo,
                                 MOUNTINFO=ReadinessTest.mountinfo(base, esp_options=esp_options),
                                 find_esp=Mock(return_value=(esp, self.guid)), check_power=Mock(),
                                 open_cabinet=Mock(return_value=nullcontext(cabinet)),
                                 fetch_cab=Mock(return_value=verify_path), verify_cab=verify),
                  patch("builtins.input", side_effect=approve)):
                if expected_error:
                    with self.assertRaisesRegex(updater.Hold, expected_error):
                        updater.main()
                    send.assert_not_called()
                    self.assertFalse(marker.exists())
                else:
                    updater.main()
                    self.assertEqual([call.args[0] for call in verify.call_args_list], [verify_path, verify_path])
                    send.assert_called_once_with([updater.FWUPDMGR, "--no-reboot-check", "local-install",
                                                  verify_path, bios["DeviceId"]], pass_fds=(23,))
                    self.assertTrue(marker.is_dir())
                self.assertEqual(catalog.call_count, 2 if esp_options == ("rw", "rw") else 0)
                if expected_output:
                    self.assertIn(expected_output, output.getvalue())

    def test_apply_rechecks_the_signed_catalog_after_approval(self):
        self.exercise_apply(self.signed_xml)
        self.exercise_apply(self.catalog_with_competitor("196608"), expected_error="上位版")
        xml = self.catalog_with_component_data('<requires><firmware compare="lt" version="1.0"/></requires>')
        self.exercise_apply(xml, expected_error="必須条件")

    def test_apply_explains_a_blocked_newer_version_and_sends_only_the_selected_cab(self):
        xml = self.catalog_with_competitor("196608")
        self.exercise_apply(xml, initial_xml=xml, policy=(None, {"b" * 64}),
                            expected_output="新版 3.0　明示ブロック")

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

    def test_apply_holds_a_cab_blocked_under_an_alias_added_after_approval(self):
        self.exercise_apply(self.catalog_with_cab_alias(), policy=(None, {"e" * 128}), expected_error="明示ブロック")

    def test_apply_refuses_a_blocked_actual_digest_missing_from_the_metadata(self):
        content = b"verified temporary CAB"
        sha256 = hashlib.sha256(content).hexdigest()
        xml = self.signed_xml.replace(b"a" * 64, sha256.encode())
        for algorithm in ("sha1", "sha512"):
            with self.subTest(algorithm=algorithm):
                blocked = hashlib.new(algorithm, content).hexdigest()
                self.exercise_apply(xml, cabinet_bytes=content, initial_xml=xml,
                                    initial_release=dict(self.published, Checksum=[sha256]),
                                    policy_after=(None, {blocked}), expected_error="明示ブロック")

    def test_apply_requires_a_signed_strong_digest_for_approval(self):
        content = b"verified temporary CAB"
        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        root = ET.fromstring(self.signed_xml.replace(b"a" * 64, sha256.encode()))
        ET.SubElement(root.find(".//artifact"), "checksum", type="sha1").text = sha1
        self.exercise_apply(ET.tostring(root), cabinet_bytes=content,
                            initial_xml=self.signed_xml.replace(b"a" * 64, sha256.encode()),
                            initial_release=dict(self.published, Checksum=[sha256]),
                            policy_after=({sha1, hashlib.sha512(content).hexdigest()}, set()),
                            expected_error="承認一覧")

    def test_apply_rechecks_which_esp_boot_order_selects_after_approval(self):
        self.exercise_apply(self.signed_xml, boot_order_after=4, expected_error="Boot0004")

    def test_apply_stops_before_marking_or_sending_on_a_read_only_esp(self):
        for opts in (("ro,nosuid", "rw"), ("rw,nosuid", "ro")):
            with self.subTest(esp_options=opts):
                self.exercise_apply(self.signed_xml, esp_options=opts, expected_error="読み取り専用")

    def test_apply_rechecks_boot_order_after_authorizing_the_request_marker(self):
        self.exercise_apply(self.signed_xml, boot_order_during_authorization=4, expected_error="Boot0004")

    def test_apply_can_recheck_an_index_that_changes_from_sha256_to_verified_sha512(self):
        content = b"verified temporary CAB"
        sha256 = hashlib.sha256(content).hexdigest().encode()
        sha512 = hashlib.sha512(content).hexdigest().encode()
        initial_xml = self.catalog_with_cab_alias().replace(b"a" * 64, sha256).replace(b"e" * 128, sha512)
        latest_xml = self.signed_xml.replace(b"a" * 64, sha512).replace(b"sha256", b"sha512")
        self.exercise_apply(latest_xml, initial_xml=initial_xml, cabinet_bytes=content,
                            initial_release=dict(self.published, Checksum=[sha256.decode()]),
                            latest_release=dict(self.published, Checksum=[sha512.decode()]))

    def test_apply_rechecks_new_signed_digests_against_the_original_cabinet(self):
        content = b"verified temporary CAB"
        sha256 = hashlib.sha256(content).hexdigest().encode()
        initial_xml = self.signed_xml.replace(b"a" * 64, sha256)
        latest_xml = self.catalog_with_cab_alias().replace(b"a" * 64, sha256)
        self.exercise_apply(latest_xml, initial_xml=initial_xml, cabinet_bytes=content,
                            initial_release=dict(self.published, Checksum=[sha256.decode()]),
                            expected_error="CABのハッシュ")

    def test_apply_keeps_checking_a_verified_digest_that_disappears_from_the_catalog(self):
        content = b"verified temporary CAB"
        sha256 = hashlib.sha256(content).hexdigest().encode()
        sha512 = hashlib.sha512(content).hexdigest().encode()
        initial_xml = self.catalog_with_cab_alias().replace(b"a" * 64, sha256).replace(b"e" * 128, sha512)
        latest_xml = self.signed_xml.replace(b"a" * 64, sha256)
        self.exercise_apply(latest_xml, initial_xml=initial_xml, cabinet_bytes=content,
                            initial_release=dict(self.published, Checksum=[sha256.decode()]),
                            policy_after=(None, {sha512.decode()}), expected_error="明示ブロック")


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

    def test_cab_artifact_linked_through_a_second_digest_contributes_its_size(self):
        bridge = (f'<artifact type="binary"><checksum type="sha256">{"a" * 64}</checksum>'
                  f'<checksum type="sha512">{"e" * 128}</checksum></artifact>')
        end = (f'<artifact type="binary"><checksum type="sha512">{"e" * 128}</checksum>'
               '<size type="download">23</size></artifact>')
        for other in (bridge + end, end + bridge):
            with self.subTest(other=other):
                with self.assertRaisesRegex(updater.Hold, "受信サイズ"):
                    updater.catalog_download_size(self.release(artifact_size='<size type="download">17</size>',
                                                              other=other))

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

    @staticmethod
    def boot_option(options=b"", *, guid=esp, name="Linux Firmware Updater", attributes=1, partition=1,
                    device_path=None, prefix=b""):
        if device_path is None:
            drive = struct.pack("<BBHIQQ16sBB", 4, 1, 42, partition, 64, 4096, guid.bytes_le, 2, 2)
            loader = "\\EFI\\example\\bootx64.efi\0".encode("utf-16-le")
            device_path = prefix + drive + struct.pack("<BBH", 4, 4, len(loader) + 4) + loader
        device_path += b"\x7f\xff\x04\x00"
        label = (name + "\0").encode("utf-16-le")
        return struct.pack("<IIH", 7, attributes, len(device_path)) + label + device_path + options

    @staticmethod
    def disk_boot_target(efivars, guid=esp):
        (efivars / f"BootOrder-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IH", 7, 3))
        (efivars / f"Boot0003-{updater.EFI_GLOBAL}").write_bytes(BootEntryTest.boot_option(guid=guid, name="Ubuntu"))

    def test_only_the_verified_boot_option_for_the_current_esp_is_reusable(self):
        expected = self.boot_option()
        profile = {"boot_entry_sha256": [hashlib.sha256(expected).hexdigest()]}
        with (TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)),
              patch.object(updater, "partition_geometry", return_value=updater.PartitionGeometry(1, 64, 4096))):
            entry = Path(tmp) / f"Boot0003-{updater.EFI_GLOBAL}"
            entry.write_bytes(expected)
            updater.check_boot_entries(str(self.esp), "8:1", profile)
            with self.assertRaises(updater.Hold):
                updater.check_boot_entries(str(uuid.UUID(int=1)), "8:1", profile)
            entry.write_bytes(self.boot_option(b"different optional data"))
            with self.assertRaises(updater.Hold):
                updater.check_boot_entries(str(self.esp), "8:1", profile)


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
                  patch.object(updater, "mount_points", return_value={
                      str(variables): updater.MountPoint(20, "0:1", "/", "efivarfs", False)}),
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
            self.assertEqual(updater.fwupd_efi_state(), ([], None))

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
              patch.object(updater, "fwupd_efi_state", return_value=([], None)),
              patch.object(updater, "boot_next", return_value=None),
              patch.object(updater, "find_esp", side_effect=updater.Hold("ESP is ambiguous")),
              patch.object(updater, "efi_variable_payload", return_value=struct.pack("<Q", 4)),
              redirect_stdout(io.StringIO()) as output):
            updater.show_reservations(str(CapsuleScopeTest.guid))
        self.assertIn("配送指示あり", output.getvalue())
        self.assertIn("ESP is ambiguous", output.getvalue())

    def test_status_preserves_disk_delivery_evidence_alongside_recovery(self):
        with (TemporaryDirectory() as tmp, patch.object(updater, "EFIVARS", Path(tmp)),
              redirect_stdout(io.StringIO()) as output):
            path = Path(tmp) / f"OsIndications-{updater.EFI_GLOBAL}"
            path.write_bytes(struct.pack("<IQ", 7, 0x44))
            updater.show_efi_variables(None)
        self.assertIn("配送指示あり", output.getvalue())
        self.assertIn("復旧指示", output.getvalue())

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
                  patch.object(updater, "mount_points", return_value={
                      str(variables): updater.MountPoint(20, "0:1", "/", "efivarfs", False)}),
                  patch.object(updater, "find_esp", return_value=(variables, str(BootEntryTest.esp))),
                  patch.object(updater, "marker_path", return_value=marker),
                  self.assertRaisesRegex(updater.Hold, "inventory unavailable")):
                updater.main()

        self.assertIn("Boot0003", output.getvalue())
        self.assertIn("この起動で更新依頼の記録があります", output.getvalue())

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
        self.assertIn("この起動で更新依頼の記録があります", output.getvalue())

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
                  patch.object(updater, "mount_points", return_value={
                      str(variables): updater.MountPoint(20, "0:1", "/", "efivarfs", False)}),
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
    @staticmethod
    def mountinfo(base, *, mount_options="rw", super_options="rw", esp_options=("rw", "rw")):
        esp, efivars = base / "esp", base / "efivars"
        path = base / "mountinfo"
        path.write_text(f"20 1 0:1 / {efivars} {mount_options} - efivarfs efivarfs {super_options}\n"
                        f"21 1 8:1 / {esp} {esp_options[0]} - vfat /dev/sda1 {esp_options[1]}\n", encoding="utf-8")
        return path

    def check_secure_boot_readiness(self, base, profile, *, mount_options="rw", super_options="rw"):
        esp, efivars = base / "esp", base / "efivars"
        platform_size = base / "fw_platform_size"
        platform_size.write_text("64\n", encoding="ascii")
        bios = {"DeviceId": "b" * 40, "Flags": ["updatable"]}
        with (patch.object(updater, "EFIVARS", efivars),
              patch.object(updater, "MOUNTINFO",
                           self.mountinfo(base, mount_options=mount_options, super_options=super_options)),
              patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
              patch.object(updater, "partition_geometry", return_value=updater.PartitionGeometry(1, 64, 4096)),
              patch.object(updater, "EFI_APP_DIR", base),
              patch.object(updater, "EFI_PLATFORM_SIZE", platform_size),
              patch.object(updater, "check_power")):
            return updater.check_ready(bios, [bios], [], profile)

    def test_cod_ignores_an_unreferenced_updater_entry_but_holds_real_bootnext(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            BootEntryTest.disk_boot_target(variables)
            old = variables / f"Boot0004-{updater.EFI_GLOBAL}"
            old.write_bytes(BootEntryTest.boot_option(guid=uuid.uuid4()))
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

            (variables / f"BootNext-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IH", 7, 4))
            with self.assertRaisesRegex(updater.Hold, "BootNext"):
                self.check_secure_boot_readiness(base, profile)

    def test_existing_os_indications_block_preparation(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 0x64))
            BootEntryTest.disk_boot_target(variables)
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            indications = variables / f"OsIndications-{updater.EFI_GLOBAL}"
            indications.write_bytes(struct.pack("<IQ", 7, 0))
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

            for flags in (4, 0x20, 0x40, 0x44):
                with self.subTest(flags=flags):
                    indications.write_bytes(struct.pack("<IQ", 7, flags))
                    with self.assertRaises(updater.Hold):
                        self.check_secure_boot_readiness(base, profile)
            indications.write_bytes(struct.pack("<II", 7, 0))
            with self.assertRaises(updater.Hold):
                self.check_secure_boot_readiness(base, profile)

    def test_disk_delivery_holds_when_pxe_is_first_active_in_boot_order(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            BootEntryTest.disk_boot_target(variables)
            (variables / f"BootOrder-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IHH", 7, 4, 3))
            pxe = variables / f"Boot0004-{updater.EFI_GLOBAL}"
            mac_path = struct.pack("<BBH", 3, 11, 37) + bytes(32) + b"\x01"
            pxe.write_bytes(BootEntryTest.boot_option(name="PXE", device_path=mac_path))
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            with self.assertRaisesRegex(updater.Hold, "Boot0004"):
                self.check_secure_boot_readiness(base, profile)

            pxe.write_bytes(BootEntryTest.boot_option(name="PXE", device_path=mac_path, attributes=0))
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")
            unverified = variables / f"Boot0003-{updater.EFI_GLOBAL}"
            unverified.write_bytes(BootEntryTest.boot_option(name="Ubuntu", partition=2))
            with self.assertRaisesRegex(updater.Hold, "Boot0003"):
                self.check_secure_boot_readiness(base, profile)

    def test_read_only_efivarfs_holds_preparation_and_can_still_show_status(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables, esp = base / "efivars", base / "esp"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            BootEntryTest.disk_boot_target(variables)
            profile = {"secure_boot": {"delivery": "capsule-on-disk"}}
            for mount_options, super_options in (("ro,nosuid", "rw"), ("rw,nosuid", "ro")):
                with self.subTest(mount=mount_options, superblock=super_options):
                    with self.assertRaisesRegex(updater.Hold, "読み取り専用"):
                        self.check_secure_boot_readiness(base, profile, mount_options=mount_options,
                                                        super_options=super_options)
                    with (patch.object(updater, "MOUNTINFO", self.mountinfo(
                            base, mount_options=mount_options, super_options=super_options)),
                          patch.object(updater, "EFIVARS", variables),
                          patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
                          redirect_stdout(io.StringIO()) as output):
                        updater.show_reservations(str(BootEntryTest.esp))
                    self.assertIn("標準の配送指示なし", output.getvalue())

    def test_read_only_esp_still_reports_existing_capsule_files(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables, esp = base / "efivars", base / "esp"
            variables.mkdir()
            delivery = esp / updater.STANDARD_CAPSULE_DIR
            delivery.mkdir(parents=True)
            (delivery / "old.cap").write_bytes(b"fixture")
            for opts in (("ro,nosuid", "rw"), ("rw,nosuid", "ro")):
                with (self.subTest(esp_options=opts),
                      patch.object(updater, "MOUNTINFO", self.mountinfo(base, esp_options=opts)),
                      patch.object(updater, "EFIVARS", variables),
                      patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
                      redirect_stdout(io.StringIO()) as output):
                    updater.show_reservations(str(BootEntryTest.esp))
                    self.assertIn(updater.STANDARD_CAPSULE_DIR, output.getvalue())

    @staticmethod
    def x64_efi_fixture():
        # DOSヘッダー、AMD64のCOFFヘッダー、PE32+のEFI Application。
        dos = bytearray(64)
        dos[:2] = b"MZ"
        struct.pack_into("<I", dos, 60, 64)
        coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664, 1, 0, 0, 0, 112, 0x22)
        optional = bytearray(112)
        struct.pack_into("<H", optional, 0, 0x20b)
        struct.pack_into("<H", optional, 68, 10)
        return bytes(dos) + coff + optional + bytes(40)

    def test_nvram_checks_the_first_loader_fwupd_would_choose_with_secure_boot_off(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            loader = base / "fwupdx64.efi"
            signed = base / "fwupdx64.efi.signed"
            image = self.x64_efi_fixture()
            signed.write_bytes(image)
            profile = {"secure_boot": {"delivery": "shim", "efi_app_dir": str(base),
                                       "fwupd_efi_sha256": hashlib.sha256(image).hexdigest()}}
            for invalid in (b"", b"non-empty broken loader"):
                with self.subTest(loader=invalid):
                    loader.write_bytes(invalid)
                    with self.assertRaisesRegex(updater.Hold, "fwupdx64.efi"):
                        self.check_secure_boot_readiness(base, profile)
            loader.unlink()
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")
            loader.write_bytes(image)
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

    def test_unrecognized_delivery_is_held_even_with_secure_boot_off(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            with self.assertRaisesRegex(updater.Hold, "配送方式"):
                self.check_secure_boot_readiness(base, {"secure_boot": {"delivery": "capsule_on_disk"}})

    def test_nvram_holds_a_persistent_zero_capability_but_cod_can_proceed(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            flag = variables / f"BootloaderSupportsFwupd-{updater.FWUPDATE_GUID}"
            flag.write_bytes(struct.pack("<IB", 7, 0))
            (base / "fwupdx64.efi").write_bytes(self.x64_efi_fixture())
            nvram = {"secure_boot": {"delivery": "shim", "efi_app_dir": str(base)}}
            with self.assertRaisesRegex(updater.Hold, "BootloaderSupportsFwupd"):
                self.check_secure_boot_readiness(base, nvram)
            flag.write_bytes(struct.pack("<IB", 6, 0))
            self.assertEqual(self.check_secure_boot_readiness(base, nvram)[0], base / "esp")

            flag.write_bytes(struct.pack("<IB", 7, 0))
            (variables / f"OsIndicationsSupported-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IQ", 7, 4))
            BootEntryTest.disk_boot_target(variables)
            self.assertEqual(self.check_secure_boot_readiness(base, {"secure_boot": {"delivery": "capsule-on-disk"}})[0],
                             base / "esp")

    def test_case_sensitive_mount_still_detects_a_capsule_in_an_uppercase_directory(self):
        with TemporaryDirectory() as tmp:
            esp = Path(tmp)
            directory = esp / "EFI" / "UPDATECAPSULE"
            directory.mkdir(parents=True)
            capsule = directory / "pending.cap"
            capsule.touch()
            iterdir = Path.iterdir

            def case_sensitive(path):
                if path.name == "UpdateCapsule":
                    raise FileNotFoundError(path)
                return iterdir(path)

            with patch.object(Path, "iterdir", new=case_sensitive):
                self.assertEqual(updater.disk_entries(esp), ["EFI/UpdateCapsule"])
                capsule.unlink()
                self.assertEqual(updater.disk_entries(esp), [])

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
            BootEntryTest.disk_boot_target(variables)
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

    def test_readiness_requires_a_confirmed_secure_boot_state(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            variables = base / "efivars"
            variables.mkdir()
            with self.assertRaisesRegex(updater.Hold, "Secure Boot"):
                self.check_secure_boot_readiness(base, {})
            (variables / f"SecureBoot-{updater.EFI_GLOBAL}").write_bytes(struct.pack("<IB", 7, 0))
            (base / "fwupdx64.efi").write_bytes(self.x64_efi_fixture())
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
            BootEntryTest.disk_boot_target(variables)
            self.assertEqual(self.check_secure_boot_readiness(base, profile)[0], base / "esp")

    def test_dell_recovery_file_blocks_preparation_without_delivery_bit(self):
        bios = {"DeviceId": "b" * 40, "Flags": ["updatable"]}
        with TemporaryDirectory() as tmp:
            esp = Path(tmp)
            previous = esp / "EFI/dell/bios/recovery/BIOS_TRS.rcv"
            previous.parent.mkdir(parents=True)
            previous.write_bytes(b"fixture")
            mount = updater.MountPoint(21, "8:1", "/", "vfat", False)
            with (patch.object(updater, "mount_points", return_value={str(esp): mount}),
                  patch.object(updater, "require_efivarfs"),
                  patch.object(updater, "find_esp", return_value=(esp, str(BootEntryTest.esp))),
                  patch.object(updater, "fwupd_efi_state", return_value=([], None)),
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
    mounts = {str(Path("/boot/efi")): updater.MountPoint(21, "8:1", "/", "vfat", False)}

    def volume(self, kind, *, mount=b"/boot/efi\0", internal=True, raid="/", number=2049):
        return {
            self.block: {"IdType": "vfat", "HintSystem": internal, "DeviceNumber": number, "MDRaid": raid},
            self.partition: {"Type": kind, "UUID": self.guid},
            self.filesystem: {"MountPoints": [mount]},
        }

    def lookup(self, objects, mounts=None, *, opened_esp=("8:1", 21)):
        with (patch.object(updater.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(self.lsblk))),
              patch.object(updater, "udisks_objects", return_value=objects, create=True),
              patch.object(updater, "mounted_path_identity", return_value=opened_esp),
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
        mounts = {**self.mounts, str(Path("/boot/efi/EFI")): updater.MountPoint(33, "8:3", "/", "ext4", False)}
        with self.assertRaisesRegex(updater.Hold, "マウント"):
            self.lookup({"/block/esp": self.volume(updater.ESP_TYPE)}, mounts=mounts)

    def test_rejects_an_esp_hidden_by_a_parent_mount(self):
        mounts = {**self.mounts, str(Path("/boot")): updater.MountPoint(33, "8:3", "/", "ext4", False)}
        for identity in (("8:3", 33), ("8:1", 33)):
            with (self.subTest(opened=identity), self.assertRaisesRegex(updater.Hold, "マウント")):
                self.lookup({"/block/esp": self.volume(updater.ESP_TYPE)}, mounts=mounts, opened_esp=identity)


class InteractiveCandidateTest(unittest.TestCase):
    def test_same_version_representations_of_one_cab_do_not_create_a_conflict(self):
        device = {"DeviceId": "b" * 40, "Version": "1.0", "VersionFormat": "pair"}
        release = dict(StableCatalogTest.published, Checksum=["a" * 64, "e" * 128])
        other = dict(release, Checksum=["e" * 128])
        with patch.object(updater, "fwupd_query", return_value=[release, other]):
            self.assertEqual(updater.candidate(device), release)
        with patch.object(updater, "fwupd_query", return_value=[release, dict(other, Checksum=["c" * 64, "e" * 128])]):
            with self.assertRaisesRegex(updater.Hold, "異なる配布物"):
                updater.candidate(device)

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


@unittest.skipUnless(shutil.which("sh"), "requires a POSIX shell")
class ShellEntryTest(unittest.TestCase):
    def run_wrapper(self, *args):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            venv = base / "venv"
            venv.mkdir()
            system_python = base / "system-python"
            for interpreter, name in ((system_python, "system"), (venv / "python3", "venv")):
                interpreter.write_bytes(f'#!/bin/sh\nprintf "%s\\n" {name} "$@"\n'.encode("ascii"))
                interpreter.chmod(0o755)
            # 本体を実行せず、ディストリビューションのPythonだけを一時ファイルに置き換える。
            source = SCRIPT.with_suffix(".sh").read_text(encoding="utf-8")
            wrapper = base / SCRIPT.with_suffix(".sh").name
            wrapper.write_bytes(source.replace("/usr/bin/python3", system_python.as_posix()).encode("utf-8"))
            env = dict(os.environ, PATH=str(venv) + os.pathsep + os.environ["PATH"])
            result = subprocess.run([shutil.which("sh"), wrapper.as_posix(), *args],
                                    env=env, capture_output=True, text=True, encoding="utf-8", check=True)
            return result.stdout.splitlines()

    def test_shell_passes_status_as_a_read_only_mode(self):
        self.assertEqual(self.run_wrapper("--status")[3:], ["--status"])

    def test_shell_uses_the_system_python_and_preserves_the_device_id(self):
        device_id = "b" * 40
        result = self.run_wrapper(device_id)
        self.assertEqual(result[0], "system")
        self.assertEqual(result[3:], ["--apply", f"--device-id={device_id}"])


class CabinetHandoffTest(unittest.TestCase):
    def test_interrupt_during_revalidation_releases_the_unsent_marker(self):
        def sudo(args, _purpose):
            if args[0] == "/usr/bin/mkdir":
                Path(args[-1]).mkdir()
            elif args[0] == "/usr/bin/rmdir":
                Path(args[-1]).rmdir()

        with (TemporaryDirectory() as tmp,
              patch.object(updater, "sudo_command", side_effect=sudo),
              patch.object(updater.subprocess, "Popen") as popen):
            marker = Path(tmp) / "marker"
            with self.assertRaises(KeyboardInterrupt):
                updater.send_once(marker, 23, Mock(side_effect=KeyboardInterrupt))
            popen.assert_not_called()
            self.assertFalse(marker.exists())

    def test_interrupt_at_or_after_install_start_keeps_the_marker(self):
        bios = {"DeviceId": "b" * 40}
        for during_start in (True, False):
            with (self.subTest(during_start=during_start), TemporaryDirectory() as tmp,
                  patch.object(updater, "sudo_command", side_effect=lambda args, purpose: Path(args[-1]).mkdir()),
                  patch.object(updater.subprocess, "Popen") as popen):
                if during_start:
                    popen.side_effect = KeyboardInterrupt
                else:
                    popen.return_value.wait.side_effect = [KeyboardInterrupt, 0]
                marker = Path(tmp) / "marker"
                with self.assertRaises(KeyboardInterrupt):
                    updater.send_once(marker, 23, lambda: bios)
                self.assertTrue(marker.is_dir())

    def test_uncertain_install_keeps_its_marker_after_session_cleanup(self):
        bios = {"DeviceId": "b" * 40}
        old_boot = "12345678-1234-1234-1234-123456789abc"
        with TemporaryDirectory() as tmp:
            run, shm = Path(tmp) / "run", Path(tmp) / "shm"
            run.mkdir()
            shm.mkdir()
            boot_id = Path(tmp) / "boot_id"
            boot_id.write_text(old_boot, encoding="ascii")
            lock_dir = run if updater.LOCK_DIR.name == "run" else shm

            def system_command(args, _purpose):
                self.assertEqual(args[0], "/usr/bin/mkdir")
                Path(args[-1]).mkdir()
                return b""

            with (patch.object(updater, "BOOT_ID", boot_id),
                  patch.object(updater, "LOCK_DIR", lock_dir),
                  patch.object(updater, "LEGACY_LOCK_DIR", shm, create=True),
                  patch.object(updater, "sudo_command", side_effect=system_command),
                  patch.object(updater.subprocess, "Popen") as popen):
                popen.return_value.wait.return_value = 1
                marker = updater.marker_path()
                with self.assertRaisesRegex(updater.Error, "未確定"):
                    updater.send_once(marker, 23, lambda: bios)
                for user_ipc in shm.iterdir():
                    user_ipc.unlink()
                with self.assertRaisesRegex(updater.Hold, "既に予約"):
                    updater.send_once(updater.marker_path(), 23, lambda: bios)
                popen.assert_called_once()
                boot_id.write_text(str(uuid.UUID(int=2)), encoding="ascii")
                updater.check_marker(updater.marker_path())

    def test_install_uses_inherited_descriptor_and_keeps_standard_dialog(self):
        bios = {"DeviceId": "b" * 40}
        fd = 23
        with (TemporaryDirectory() as tmp,
              patch.object(updater, "sudo_command", side_effect=lambda args, purpose: Path(args[-1]).mkdir()),
              patch.object(updater.subprocess, "Popen") as popen):
            popen.return_value.wait.return_value = 0
            updater.send_once(Path(tmp) / "marker", fd, lambda: bios)
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
