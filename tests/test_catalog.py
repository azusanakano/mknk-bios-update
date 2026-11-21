"""Firmware and daemon fixtures only. No host device, system bus or network access."""
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.request import Request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import catalog
from firmware_api import fw


GUID = "12345678-1234-1234-1234-123456789abc"
DEVICE = "a" * 40
CAB_DIGEST = hashlib.sha256(b"cab").hexdigest()
URI = sorted(fw.LVFS_METADATA_URIS)[0]
REMOTE = dict(Id="lvfs", Kind="download", Enabled=True, MetadataUri=URI, MetadataUriSig=URI + ".jcat")


def metadata(version="2", requirements=""):
    return f"""<components><component type="firmware"><id>com.example.Bios</id>
    <provides><firmware type="flashed">{GUID}</firmware></provides>{requirements}
    <releases><release version="{version}"><description><p>New <em>BIOS</em></p></description>
    <checksum type="sha256" target="container">{CAB_DIGEST}</checksum>
    </release></releases></component></components>""".encode()


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.device = dict(DeviceId=DEVICE, Version="1", VersionFormat="number", Guid=[GUID],
                           Flags=["internal", "updatable"], Protocols=[fw.PROTOCOL], Plugin="uefi_capsule")
        self.release = dict(AppstreamId="com.example.Bios", Version="2", RemoteId="lvfs", Checksum=[CAB_DIGEST])
        self.devices = [self.device, dict(DeviceId="b" * 40, Flags=["internal"], Plugin="nvme", Guid=[GUID])]
        self.queries = []
        self.upgrades = [self.release]
        self.releases = [self.release]
        self.policy = (None, set())
        self.xml = metadata()
        self.cached = None
        self.session = Mock(owner=":1.4", version="2.0.20")
        self.session.current_owner.return_value = self.session.owner
        self.session.rows.side_effect = self.rows
        self.session.policy.side_effect = lambda remote: self.policy
        self.session.remote.return_value = REMOTE
        self.enterContext(patch.object(catalog, "Session", return_value=self.session))
        self.enterContext(patch.object(fw, "read_settings", return_value={}))
        self.enterContext(patch.object(catalog, "download", side_effect=self.pair))
        self.enterContext(patch.object(catalog, "signing_time", side_effect=lambda md, sig: int(sig)))
        self.enterContext(patch.object(catalog, "cache_pair", side_effect=self.cache))

    def pair(self, remote, settings=None, session=None):
        return lzma.compress(self.xml), b"50"

    def cache(self, remote):
        if isinstance(self.cached, Exception):
            raise self.cached
        return self.cached or self.pair(remote)

    def rows(self, operation, *args):
        self.queries.append((operation, args))
        return {"get_devices": self.devices, "get_upgrades": self.upgrades,
                "get_releases": self.releases, "search": []}[operation]

    def test_read_only_check_returns_signed_text_and_correct_device(self):
        report = catalog.query("check", GUID)
        self.assertEqual(report["state"], "available", report)
        self.assertEqual(report["changes"], "New BIOS")
        self.assertEqual(report["device"], DEVICE)
        self.assertEqual(report["appstream_id"], "com.example.Bios")
        self.assertEqual(report["daemon_owner"], ":1.4")
        self.assertEqual(report["catalog_sha256"], hashlib.sha256(self.xml).hexdigest())
        self.assertEqual(report["signed_timestamp"], 50)
        self.assertTrue(report["checked"])
        self.assertTrue(all(args == (DEVICE,) for op, args in self.queries if op != "get_devices"))
        self.assertNotIn("checksum", report)
        self.assertEqual(report["token"], catalog.query("check", GUID)["token"])

    def test_current_requires_both_model_and_index(self):
        self.set_current_release()
        report = catalog.query("check", GUID)
        self.assertEqual(report["state"], "current", report)
        self.releases = []
        self.assertTrue(catalog.query("check", GUID)["refresh_required"])
        self.xml = self.xml.replace(GUID.encode(), ("c" * 36).encode())
        self.assertEqual(catalog.query("check", GUID)["state"], "hold")

    def set_current_release(self):
        self.xml = metadata(version="1")
        self.upgrades = []
        self.releases = [dict(self.release, Version="1")]

    def test_unsupported_client_feature_never_becomes_eligible(self):
        self.xml = metadata(requirements="<requires><client>requests</client></requires>")
        self.assertIn("requests", catalog.query("check", GUID)["detail"])

    def test_source_and_admin_approval_must_match(self):
        self.releases = [dict(self.release, RemoteId="lvfs-testing")]
        self.assertTrue(catalog.query("check", GUID)["refresh_required"])
        self.releases = [dict(self.release, Flags=["blocked-approval"])]
        self.assertEqual(catalog.query("check", GUID)["state"], "hold")
        self.releases = [self.release]
        self.policy = (set(), set())
        self.assertIn("承認", catalog.query("check", GUID)["detail"])
        self.policy = ({CAB_DIGEST}, {CAB_DIGEST})
        self.assertIn("ブロック", catalog.query("check", GUID)["detail"])

    def test_remote_generation_and_cache_evidence(self):
        self.cached = FileNotFoundError()
        report = catalog.query("check", GUID)
        self.assertTrue(report["refresh_required"])
        self.assertFalse(report["checked"])
        self.cached = (lzma.compress(metadata("3")), b"55")
        report = catalog.query("check", GUID)
        self.assertNotIn("refresh_required", report)
        self.assertEqual(report["signed_timestamp"], 55)
        self.assertEqual(report["catalog_sha256"], hashlib.sha256(metadata("3")).hexdigest())
        self.cached = (lzma.compress(self.xml, preset=1), b"55")
        report = catalog.query("check", GUID)
        self.assertEqual(report["state"], "available", report)
        self.assertEqual(report["signed_timestamp"], 55)

    def test_changed_daemon_owner_invalidates_candidate(self):
        self.session.current_owner.return_value = ":1.14"
        report = catalog.query("check", GUID)
        self.assertEqual(report["state"], "hold")
        self.assertNotIn("token", report)

    def test_revalidate_rechecks_hashes_policy_and_never_fetches_cab(self):
        plan = dict(payload_sha256="b" * 64, scope="FMP画像1件", checksum=CAB_DIGEST)
        with patch.object(fw, "support_profile", return_value={}), patch.object(
                catalog, "verified_payload", return_value=(plan, {"f" * 40})) as verify:
            original = catalog.query("prepare", GUID, object())
            rechecked = catalog.query("revalidate", GUID, object())
            self.assertEqual(original["state"], "available", original)
            self.assertEqual(original["token"], rechecked["token"])
            self.assertEqual(verify.call_args.args[1], "revalidate")
            self.policy = (None, {"f" * 40})
            self.assertEqual(catalog.query("revalidate", GUID, object())["state"], "hold")

    def test_signature_failure_is_sanitized_and_does_not_advance_generation(self):
        with patch.object(catalog, "signing_time", side_effect=ValueError("PRIVATE-URI")):
            report = catalog.query("check", GUID)
        self.assertEqual(report["state"], "hold")
        self.assertNotIn("PRIVATE", str(report))
        self.assertNotIn("signed_timestamp", report)

    def test_mirror_requires_explicit_id_and_uri(self):
        mirror = dict(REMOTE, Id="firmware-stable", MetadataUri="https://mirror.example/downloads/bios.xml.xz")
        with self.assertRaises(fw.Hold):
            fw.stable_remote({}, remotes=[mirror], remote_id=mirror["Id"])
        allowed = dict(stable_metadata_uris=[mirror["MetadataUri"]])
        self.assertEqual(fw.stable_remote(allowed, remotes=[mirror], remote_id=mirror["Id"]), mirror)
        with self.assertRaises(fw.Hold):
            fw.stable_remote(allowed, remotes=[dict(mirror, Password="secret")], remote_id=mirror["Id"])

    def test_metadata_destinations_and_mirror_auth_are_resource_scoped(self):
        base = "https://mirror.example/lvfs/firmware.xml.xz"
        good = "https://mirror.example/lvfs/firmware-00001-stable.xml.xz"
        self.assertTrue(catalog.metadata_uri_allowed(good, base))
        self.assertFalse(catalog.metadata_uri_allowed(good.replace("stable", "testing"), base))
        self.assertFalse(catalog.metadata_uri_allowed(good.replace("lvfs/", "other/"), base))
        self.assertFalse(catalog.metadata_uri_allowed(good.replace("mirror.", "elsewhere."), base))
        account = dict(Username="a", Password="b")
        target = catalog.with_auth(base, account)
        protected = catalog.ResourceAuth(account, {target})
        request = protected.https_request(Request(target))
        self.assertTrue(request.has_header("Authorization"))
        self.assertNotIn("Authorization", request.headers)
        handler = catalog.CatalogRedirect({target, good})
        redirected = handler.redirect_request(request, io.BytesIO(), 302, "", {}, good)
        self.assertFalse(protected.https_request(redirected).has_header("Authorization"))
        with self.assertRaises(fw.Hold):
            handler.redirect_request(request, io.BytesIO(), 302, "", {}, "https://elsewhere.example/secret")

    def test_remote_fence_tracks_destination_and_policy_across_cache_refresh(self):
        identity = catalog.remote_fingerprint(REMOTE)
        for field, value in (("Id", "other"), ("MetadataUri", "https://mirror.example/stable.xml.xz"),
                             ("ApprovalRequired", True), ("FilenameCache", "/another/cache")):
            self.assertNotEqual(catalog.remote_fingerprint(dict(REMOTE, **{field: value})), identity)
        self.assertEqual(catalog.remote_fingerprint(dict(REMOTE, Mtime=50, Checksum="a" * 64)), identity)

    def test_approved_capsule_digest_and_size_refer_to_payload_inside_cab(self):
        guid_bytes = uuid.UUID(GUID).bytes_le
        image = struct.pack("<I16sB3xII", 1, guid_bytes, 1, 1, 0) + b"x"
        fmp = struct.pack("<IHHQ", 1, 0, 1, 16) + image
        payload = fw.FMP_CAPSULE + struct.pack("<III", 28, 0, 28 + len(fmp)) + fmp
        profile = dict(fmp=dict(image_type_id=GUID, image_index=1, hardware_instance=0))
        xml = b'<component><id>com.example.Bios</id><releases><release version="2"/></releases></component>'
        details = [dict(Guid=[GUID], Releases=[dict(self.release, Flags=["trusted-payload"])])]
        self.session.rows.side_effect = lambda *args: details
        with tempfile.TemporaryFile() as cabinet, patch.object(catalog, "sealed_size", return_value=3), patch.object(
                fw, "read_cab_files", side_effect=lambda path, name=None:
                {name: payload} if name else {"bios.metainfo.xml": xml}), patch.object(catalog, "fetch_release") as fetch:
            cabinet.write(b"cab")
            plan, actual = catalog.verified_payload(cabinet, "revalidate", self.release, REMOTE,
                                    fw.CatalogCheck(3, True, {"sha256": CAB_DIGEST}, None),
                                    self.device, self.devices, GUID, profile, self.session)
        fetch.assert_not_called()
        self.assertEqual(plan["payload_size"], len(payload))
        self.assertEqual(plan["payload_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(plan["checksum"], CAB_DIGEST)
        self.assertEqual(plan["cab_sha512"], hashlib.sha512(b"cab").hexdigest())
        self.assertIn(CAB_DIGEST, actual)
        self.assertEqual(plan["target_raw"], 2)

    @unittest.skipUnless(hasattr(os, "memfd_create"), "Linux sealable memfd")
    def test_metadata_fds_are_verified_sealed_and_rewound(self):
        self.cached = FileNotFoundError()
        with fw.open_cabinet() as data, fw.open_cabinet() as sig:
            report = catalog.fetch_metadata(GUID, data, sig)
            self.assertEqual(report["state"], "metadata", report)
            self.assertEqual(report["compressed_sha256"], hashlib.sha256(data.read()).hexdigest())
            self.assertEqual(sig.read(), b"50")
            for stream in (data, sig):
                with self.assertRaises(OSError):
                    os.ftruncate(stream.fileno(), 0)


@unittest.skipUnless(sys.platform.startswith("linux"), "Ubuntu system GI libraries")
class NativeCatalogTests(unittest.TestCase):
    def test_signed_catalog_through_installed_libraries(self):
        import gi
        gi.require_version("Jcat", "1.0")
        from gi.repository import Jcat
        Fwupd, GLib = fw.fwupd_bindings()

        payload = lzma.compress(metadata())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trust = root / "trust"
            trust.mkdir()
            cert = trust / "fixture.pem"
            key = root / "private.key"
            subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=Disposable catalog test",
                            "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
                            "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            signed = subprocess.run(["/usr/bin/openssl", "smime", "-sign", "-binary", "-md", "sha256",
                                     "-outform", "PEM", "-signer", str(cert), "-inkey", str(key)],
                                    check=True, input=payload, capture_output=True).stdout.decode("ascii")
            immutable = "firmware-00123-stable.xml.xz"
            checksum = dict(Kind=int(Jcat.BlobKind.SHA256), Flags=1, Data=hashlib.sha256(payload).hexdigest())
            pkcs7 = dict(Kind=int(Jcat.BlobKind.PKCS7), Flags=1, Data=signed)

            def jcat(blobs):
                item = dict(Id=immutable, AliasIds=["firmware.xml.xz"], Blobs=blobs)
                return gzip.compress(json.dumps(dict(JcatVersionMajor=0, JcatVersionMinor=1, Items=[item])).encode())

            signature = jcat([checksum, pkcs7])
            with patch.object(catalog, "TRUST_DIRECTORIES", (str(trust),)), patch.dict(
                    os.environ, {"MKNK_FWUPD_ONLY_PQ": "0"}):
                components, identity = catalog.authenticated(payload, signature, {GUID})
                self.assertEqual(len(components), 1)
                self.assertEqual(identity["catalog_sha256"], hashlib.sha256(metadata()).hexdigest())
                self.assertGreater(identity["signed_timestamp"], 1)
                # Recompute the checksum for tampered bytes; the PKCS#7 check must still fail.
                changed = lzma.compress(metadata("3"))
                tampered = jcat([dict(checksum, Data=hashlib.sha256(changed).hexdigest()), pkcs7])
                with self.assertRaises(fw.Hold):
                    catalog.authenticated(changed, tampered, {GUID})
                for untrusted in (jcat([checksum]), jcat([pkcs7])):
                    with self.assertRaises(fw.Hold):
                        catalog.authenticated(payload, untrusted, {GUID})
                with patch.object(catalog, "TRUST_DIRECTORIES", ()), self.assertRaises(fw.Hold):
                    catalog.authenticated(payload, signature, {GUID})

            # Decode the genuine GetRemotes row type and exercise public Remote methods
            # without a system bus or a firmware daemon.
            remote = Fwupd.Remote.new()
            original = "https://mirror.example/downloads/firmware.xml.xz"
            base = "https://mirror.example/cabs"
            fields = {"RemoteId": "example", "Uri": original, "FirmwareBaseUri": base,
                      "Username": "test", "Password": "fixture"}
            self.assertTrue(remote.from_variant(GLib.Variant("a{sv}", {
                k: GLib.Variant("s", v) for k, v in fields.items()})))
            self.assertEqual(json.loads(remote.to_json_string(Fwupd.CodecFlags.NONE))["MetadataUri"], original)
            self.assertEqual(remote.get_metadata_uri_sig(), original + ".jcat")
            self.assertTrue(remote.load_signature_bytes(GLib.Bytes.new(signature)))
            self.assertTrue(remote.get_metadata_uri().endswith("/" + immutable))
            self.assertEqual(catalog.protected_uri(remote.build_firmware_uri("https://lvfs.example/file.cab")),
                             base + "/file.cab/auth")

    def test_installed_query_signatures_and_error_domain(self):
        Fwupd, GLib = fw.fwupd_bindings()
        signatures = {
            "set_feature_flags": ("feature_flags", "cancellable"),
            "get_remotes": ("cancellable",), "get_devices": ("cancellable",),
            "get_remote_by_id": ("remote_id", "cancellable"), "get_details": ("filename", "cancellable"),
            "get_upgrades": ("device_id", "cancellable"), "get_releases": ("device_id", "cancellable"),
            "get_approved_firmware": ("cancellable",), "get_blocked_firmware": ("cancellable",),
            "search": ("token", "cancellable"), "get_daemon_version": (),
        }
        for name, names in signatures.items():
            with self.subTest(name=name):
                info = getattr(Fwupd.Client, name)
                self.assertEqual(tuple(arg.get_name() for arg in info.get_arguments()), names)
        self.assertEqual(int(Fwupd.FeatureFlags.NONE), 0)
        self.assertTrue(callable(Fwupd.Device.get_composite_id))
        with self.assertRaises(GLib.Error) as rejected:
            Fwupd.Remote.new().from_variant(GLib.Variant("i", 1))
        self.assertEqual(rejected.exception.domain, "FwupdError")
        error = GLib.Error.new_literal(GLib.quark_from_string(rejected.exception.domain),
                                       "empty", Fwupd.Error.NOTHING_TO_DO)
        session = catalog.Session.__new__(catalog.Session)
        session.GLib, session.Fwupd, session.client = GLib, Fwupd, Mock()
        session.client.get_upgrades.side_effect = error
        self.assertEqual(session.rows("get_upgrades", DEVICE), [])
        session.client.get_upgrades.side_effect = rejected.exception
        with self.assertRaises(fw.Hold):
            session.rows("get_upgrades", DEVICE)


if __name__ == "__main__":
    unittest.main()
