#!/usr/bin/python3
"""Build the x86_64 AppImage from this checkout and distribution libraries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SHA256 = "617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46"
HOST_LIBS = {"libc.so.6", "libm.so.6", "libmvec.so.1", "libpthread.so.0", "libdl.so.2",
             "librt.so.1", "libresolv.so.2", "libutil.so.1", "libanl.so.1", "ld-linux-x86-64.so.2"}


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def output(args):
    return subprocess.check_output(args, text=True, env=dict(os.environ, LC_ALL="C"))


def verify_runtime(runtime, expected):
    raw = runtime.read_bytes()
    if (hashlib.sha256(raw).hexdigest() != expected or raw[:5] != b"\x7fELF\x02"
            or raw[18:20] != b"\x3e\x00" or raw[8:11] != b"AI\x02"):
        raise ValueError("AppImage runtime is not the expected x86_64 type-2 binary (SHA-256 mismatch or bad header)")


def shared_libraries(inputs):
    """ldd reports the transitive closure of these trusted build-host binaries."""
    result = {}
    for binary in inputs:
        lines = output(["ldd", str(binary)])
        if "=> not found" in lines:
            raise RuntimeError(f"missing dependency for {binary}: {lines.strip()}")
        for name, filename in re.findall(r"^\s*(\S+)\s+=>\s+(/\S+)\s+\(", lines, re.M):
            if name not in HOST_LIBS:
                result[name] = Path(filename).resolve()
    return result


def gi_payload(libdir):
    import gi
    gi_root = Path(gi.__file__).resolve().parent
    items = {"backend/gi/" + p.relative_to(gi_root).as_posix(): p for p in gi_root.rglob("*.py")}
    extension = next(gi_root.glob("_gi.cpython-312-*.so"))
    items["backend/gi/" + extension.name] = extension
    libs = {"libarchive.so.13": (libdir / "libarchive.so.13").resolve(strict=True)}
    pending = {"Gio-2.0", "GLib-2.0", "Fwupd-2.0", "Jcat-1.0"}
    seen = set()
    while pending:
        identifier = pending.pop()
        seen.add(identifier)
        namespace, version = identifier.rsplit("-", 1)
        typelibs = libdir / "girepository-1.0"
        items["typelibs/" + identifier + ".typelib"] = (typelibs / (identifier + ".typelib")).resolve(strict=True)
        metadata = output(["g-ir-inspect", "--version=" + version, "--print-typelibs", "--print-shlibs", namespace])
        for line in metadata.splitlines():
            kind, _, name = line.partition(": ")
            if kind == "typelib" and name not in seen:
                pending.add(name)
            elif kind == "shlib":
                libs[name] = (libdir / name).resolve(strict=True)
    libs.update(shared_libraries([extension, *libs.values()]))
    items.update({"lib/" + name: filename for name, filename in libs.items()})
    return items


def copy(source, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    return dest


def write_helper(dest, gui, items):
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(["cc", "-std=c17", "-Os", "-Wall", "-Wextra", "-Werror", "-s", "-Wl,-z,relro,-z,now",
         str(ROOT / "portable/helper.c"), "-o", str(dest)])
    files = {"payload/" + name: src for name, src in items.items()}
    files.update({"payload/backend/" + p.name: p for p in (ROOT / "backend").glob("*.py")})
    files["payload/backend/firmware.py"] = ROOT / "mknk-bios-update-design-and-sample/mknk-bios-update.py"
    files["payload/backend/io.github.mknk.BiosUpdate1.xml"] = ROOT / "data/io.github.mknk.BiosUpdate1.xml"
    files["__main__.py"] = ROOT / "portable/bootstrap.py"
    with zipfile.ZipFile(dest, "a", compression=zipfile.ZIP_STORED) as archive:
        for name, source in sorted(files.items()):
            with source.open("rb") as src, archive.open(zipfile.ZipInfo(name), "w") as out:
                shutil.copyfileobj(src, out)
        archive.writestr(zipfile.ZipInfo("payload/backend/gui.sha256"), hashlib.sha256(gui.read_bytes()).hexdigest())
    dest.chmod(0o755)


def desktop_assets(app, share):
    desktop_name = "io.github.mknk.BiosUpdate.desktop"
    original = (ROOT / "data" / desktop_name).read_text()
    desktop = share / "applications" / desktop_name
    desktop.parent.mkdir(parents=True)
    desktop.write_text(original.replace("Exec=/usr/bin/mknk-bios-update", "Exec=mknk-bios-update"))
    (app / desktop_name).symlink_to(desktop.relative_to(app))
    theme = Path("/usr/share/icons/Adwaita")
    png = sorted(theme.rglob("computer.png"), key=lambda f: f.stat().st_size, reverse=True)
    destination = share / "icons/hicolor/128x128/devices/computer.png"
    if png:
        original_icon = png[0]
        copy(original_icon, destination)
    else:
        original_icon = next(theme.rglob("computer-symbolic.svg"))
        destination.parent.mkdir(parents=True)
        run(["rsvg-convert", "-w", "128", "-h", "128", "-o", str(destination), str(original_icon)])
    (app / "computer.png").symlink_to(destination.relative_to(app))
    (app / ".DirIcon").symlink_to("computer.png")
    schemas = list(Path("/usr/share/glib-2.0/schemas").glob("org.gtk.*.xml"))
    if schemas:
        directory = share / "glib-2.0/schemas"
        for schema in schemas:
            copy(schema, directory / schema.name)
        run(["glib-compile-schemas", "--strict", str(directory)])
    return [original_icon, *schemas]


def install_notices(share, sources, runtime_license):
    docs = share / "doc/mknk-bios-update"
    copy(ROOT / "README.md", docs / "README.md")
    for path in ("docs/superpowers/specs/2026-11-21-linux-bios-updater-design.md",
                 "mknk-bios-update-design-and-sample/Linux-BIOS-Updater-Design.md"):
        copy(ROOT / path, docs / path)
    notices = docs / "third-party"
    copy(runtime_license, notices / "AppImage-runtime.LICENSE")
    paths = set()
    for item in sources:
        canonical = str(item.resolve())
        paths.add(canonical)
        if canonical.startswith(("/usr/lib/", "/usr/bin/", "/usr/sbin/")):
            paths.add(canonical[4:])
    owners = set()
    for listing in Path("/var/lib/dpkg/info").glob("*.list"):
        if paths.intersection(listing.read_text(errors="replace").splitlines()):
            owners.add(listing.name[:-5])
    for package in owners:
        short = package.split(":")[0]
        copy(Path("/usr/share/doc") / short / "copyright", notices / short / "copyright")
    fmt = r"${binary:Package}\t${source:Package}\t${source:Version}\n"
    (notices / "packages.tsv").write_text(output(["dpkg-query", "-W", "-f=" + fmt, *sorted(owners)]))
    shutil.copytree("/usr/share/common-licenses", notices / "common-licenses")


def build(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or sys.version_info[:2] != (3, 12):
        raise ValueError("build on Ubuntu 24.04 x86_64 using /usr/bin/python3")
    verify_runtime(args.runtime, args.runtime_sha256)
    runtime_license = args.runtime_license or args.runtime.with_name(args.runtime.name + ".LICENSE")
    if not runtime_license.is_file():
        raise ValueError("pass --runtime-license with the matching type2-runtime LICENSE")
    if not (args.build_dir / "meson-private/coredata.dat").exists():
        run(["meson", "setup", str(args.build_dir), str(ROOT), "--buildtype=release", "--prefix=/usr", "--sysconfdir=/etc"])
    run(["meson", "compile", "-C", str(args.build_dir), "mknk-bios-update"])
    image_path = args.output
    if image_path is None:
        project = json.loads(output(["meson", "introspect", "--projectinfo", str(args.build_dir)]))
        image_path = ROOT / "dist" / f"mknk-bios-update-{project['version']}-x86_64.AppImage"
    image_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".appimage-", dir=image_path.parent) as tmp:
        work = Path(tmp)
        app = work / "AppDir"
        lib = app / "usr/lib"
        gui = copy(args.build_dir / "mknk-bios-update", app / "usr/bin/mknk-bios-update")
        run(["strip", "--strip-unneeded", str(gui)])
        gui.chmod(0o755)
        copy(ROOT / "portable/launcher.py", app / "AppRun").chmod(0o755)
        gui_libs = shared_libraries([gui])
        for name, source in gui_libs.items():
            copy(source, lib / "gui" / name)
        helpers = gi_payload(Path("/usr/lib") / sysconfig.get_config_var("MULTIARCH"))
        write_helper(lib / "mknk-bios-update/portable-helper", gui, helpers)
        share = app / "usr/share"
        assets = desktop_assets(app, share)
        install_notices(share, [*gui_libs.values(), *helpers.values(), *assets], runtime_license)
        fs = work / "image.squashfs"
        run(["mksquashfs", str(app), str(fs), "-noappend", "-all-root", "-no-progress",
             "-comp", "zstd", "-Xcompression-level", "9", "-processors", str(args.jobs)])
        image = copy(args.runtime, work / "release.AppImage")
        with fs.open("rb") as src, image.open("ab") as out:
            shutil.copyfileobj(src, out)
        image.chmod(0o755)
        image.replace(image_path)
    print(image_path, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--runtime-license", type=Path)
    parser.add_argument("--runtime-sha256", default=RUNTIME_SHA256)
    parser.add_argument("--jobs", type=int, default=1, choices=range(1, 65), metavar="1-64")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/appimage-native")
    parser.add_argument("--output", type=Path, help="default: dist/mknk-bios-update-<version>-x86_64.AppImage")
    build(parser.parse_args())
