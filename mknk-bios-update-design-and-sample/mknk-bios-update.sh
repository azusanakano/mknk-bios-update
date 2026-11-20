#!/bin/sh
# mknk-bios-update.sh — ネコシステム社
# Python 版と同じ照合・承認を通して、システム BIOS の更新を予約する。

usage() {
    printf '%s\n' \
        '使い方: sh mknk-bios-update.sh [Device ID]' \
        '引数を省略すると、実機のシステム BIOS を自動で特定します。' \
        '指定する場合は、自動で特定した BIOS と同じ Device ID を入力してください。'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'python3 が見つかりません。ディストリビューションの python3 を使用してください。' >&2
    exit 1
fi
if [ "$#" -eq 1 ]; then
    set -- "--device-id=$1"
fi
script_dir=$(dirname -- "$0") || exit 1
exec python3 -- "$script_dir/mknk-bios-update.py" --apply "$@"
