"""Load the same validation code used by the shipped CLI, without interactive privilege fallback."""
import importlib.util
from pathlib import Path


_dir = Path(__file__).resolve().parent
_source = _dir / "firmware.py"
if not _source.is_file():
    _source = _dir.parent / "mknk-bios-update-design-and-sample" / "mknk-bios-update.py"
_spec = importlib.util.spec_from_file_location("mknk_firmware", _source)
fw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fw)


def _protected_read(args, purpose):
    raise fw.Hold(f"{purpose}に必要な情報を読み取れません。")


fw.sudo_command = _protected_read
