#!/bin/sh
# mknk-bios-update.sh — ネコシステム社
# Python 版と同じ照合・承認を通して、システム BIOS の更新を予約する。

usage() {
    printf '%s\n' \
        '使い方　sh mknk-bios-update.sh [Device ID | --status]' \
        '引数を省略すると、実機のシステム BIOS を自動で特定します。' \
        '指定する場合は、自動で特定した BIOS と同じ Device ID を入力してください。' \
        '--status は実機のBIOS版と更新の予約・履歴を表示します。'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 1
fi
python="/usr/bin/python3"
if [ ! -x "$python" ]; then
    printf '%s\n' 'ディストリビューションの Python（/usr/bin/python3）を実行できません。' >&2
    exit 1
fi
mode="--apply"
if [ "$#" -eq 1 ]; then
    case "$1" in
        --status) mode="--status"; shift ;;
        *) set -- "--device-id=$1" ;;
    esac
fi
script_dir=$(dirname -- "$0") || exit 1
exec "$python" -- "$script_dir/mknk-bios-update.py" "$mode" "$@"
