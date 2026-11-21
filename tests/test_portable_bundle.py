"""Packaging boundaries for the copy-and-run image."""
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portable import bootstrap, build_image, launcher


class PortableBundleTests(unittest.TestCase):
    def test_helper_uses_a_protected_executable_mount_for_its_libraries(self):
        safe = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        writable = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777)
        with (patch.object(os, "ST_NOEXEC", 8, create=True),
              patch.object(os, "ST_RDONLY", 1, create=True),
              patch.object(os, "lstat", side_effect=[safe, safe, writable, safe]),
              patch.object(os, "statvfs", side_effect=[SimpleNamespace(f_flag=x) for x in (8, 0, 1)], create=True)):
            self.assertEqual(bootstrap.stage_parent(), "/var/cache")
            with self.assertRaises(RuntimeError):
                bootstrap.stage_parent()

    def test_helper_extracts_only_embedded_payload_files(self):
        with tempfile.TemporaryDirectory() as tmp, io.BytesIO() as buf:
            with zipfile.ZipFile(buf, "w") as out:
                out.writestr("__main__.py", "bootstrap")
                out.writestr("payload/backend/portable_service.py", "service")
                out.writestr("payload/backend/gi/__init__.py", "bindings")
                out.writestr("payload/lib/libexample.so.1", b"library")
            tree = Path(tmp)
            with zipfile.ZipFile(buf) as archive:
                bootstrap.extract_payload(archive, tree)
            self.assertEqual((tree / "backend/portable_service.py").read_text(), "service")
            self.assertEqual((tree / "lib/libexample.so.1").read_bytes(), b"library")
            self.assertFalse((tree / "__main__.py").exists())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE((tree / "backend/gi").stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((tree / "lib/libexample.so.1").stat().st_mode), 0o644)

    def test_helper_rejects_unexpected_roots_traversal_and_symlinks(self):
        for name, kind in (("payload/../escaped", stat.S_IFREG), ("/absolute", stat.S_IFREG),
                           ("payload/etc/setting", stat.S_IFREG), ("payload/lib/link", stat.S_IFLNK)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp, io.BytesIO() as buf:
                with zipfile.ZipFile(buf, "w") as out:
                    entry = zipfile.ZipInfo(name)
                    entry.external_attr = (kind | 0o777) << 16
                    out.writestr(entry, "dummy")
                with zipfile.ZipFile(buf) as archive, self.assertRaises(ValueError):
                    bootstrap.extract_payload(archive, Path(tmp))

    def test_privileged_environment_only_uses_root_staging_and_authenticating_uid(self):
        stage = Path("/run/mknk-test")
        env = bootstrap.service_environment(stage, "1000")
        self.assertEqual(env["PKEXEC_UID"], "1000")
        self.assertEqual(env["LD_LIBRARY_PATH"], str(stage / "lib"))
        self.assertEqual(env["GI_TYPELIB_PATH"], str(stage / "typelibs"))
        self.assertFalse({"PYTHONPATH", "LD_PRELOAD", "APPDIR", "DBUS_SYSTEM_BUS_ADDRESS"} & env.keys())

    def test_rejects_a_different_runtime_before_packaging(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.write_bytes(b"not the pinned runtime")
            with self.assertRaises(ValueError):
                build_image.verify_runtime(runtime, "0" * 64)

    @unittest.skipUnless(sys.platform == "linux", "Linux executable memfd")
    def test_gui_inode_is_immutable_and_independent_of_the_image_mount(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "gui"
            source.write_bytes(b"native GUI fixture")
            gui = launcher.sealed_gui(source)
            try:
                source.unlink()
                self.assertEqual(os.read(gui, 40), b"native GUI fixture")
                self.assertTrue(fcntl.fcntl(gui, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE)
                with self.assertRaises(OSError):
                    os.write(gui, b"changed")
            finally:
                os.close(gui)
