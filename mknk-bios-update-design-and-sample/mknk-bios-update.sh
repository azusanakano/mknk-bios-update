#!/bin/sh
# mknk-bios-update.sh — ネコシステム社
# Linux の端末から、選択したシステム BIOS の更新を fwupd に依頼する。
# 使い方: sh mknk-bios-update.sh [Device ID]

usage() {
    printf '%s\n' \
        '使い方: sh mknk-bios-update.sh [Device ID]' \
        '引数を省略すると一覧の表示後に入力できます。' \
        '本体のシステム BIOS（例: System Firmware）の Device ID を使用してください。'
}

case "${1-}" in
    -h|--help) usage; exit 0 ;;
esac
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 1
fi
if ! command -v fwupdmgr >/dev/null 2>&1; then
    printf '%s\n' 'fwupdmgr が見つかりません。fwupd パッケージをインストールしてください。' >&2
    exit 1
fi
if [ ! -t 0 ] || [ ! -t 1 ]; then
    printf '%s\n' '機器名と更新内容を確認できる対話端末で実行してください。' >&2
    exit 1
fi

# Device ID を指定できない旧版で、機器全体への更新が走るのを防ぐ。
if ! LC_ALL=C fwupdmgr --help | grep -Eq '^[[:space:]]*update[[:space:]]+\[?DEVICE[-_]ID'; then
    printf '%s\n' 'この fwupdmgr では Device ID を指定する update の構文を確認できません。' >&2
    exit 1
fi

# fwupdmgr の終了値 2 は「処理対象なし」。そのほかのエラーは呼び出し元に返す。
stop_after_query() {
    if [ "$1" -eq 2 ]; then
        printf '%s\n' "$2"
        exit 0
    fi
    exit "$1"
}

fwupdmgr refresh || {
    status=$?
    [ "$status" -eq 2 ] || exit "$status"
}
fwupdmgr get-devices || stop_after_query "$?" '列挙できる機器がありません。'
fwupdmgr get-updates || stop_after_query "$?" '利用できる更新候補がありません。'

if [ "$#" -eq 0 ]; then
    printf '\n%s\n' '本体のシステム BIOS（例: System Firmware）を探してください。'
    printf '%s' 'その機器の Device ID を貼り付けてください（空の Enter で終了）: '
    IFS= read -r device_id || exit 0
else
    device_id=$1
fi
[ -n "$device_id" ] || exit 0
case "$device_id" in
    *[!0123456789abcdefABCDEF]*) valid=false ;;
    *) valid=true ;;
esac
if [ "$valid" != true ] || [ "${#device_id}" -ne 40 ]; then
    printf '%s\n' 'Device ID は40桁の16進数です。対象機器の Device ID 欄をコピーしてください。' >&2
    exit 1
fi
device_id=$(printf '%s' "$device_id" | tr 'ABCDEF' 'abcdef') || exit 1

printf '\n対象の Device ID: %s\n' "$device_id"
fwupdmgr get-updates "$device_id" || stop_after_query "$?" '指定した機器には利用できる更新候補がありません。'
printf '%s\n' '上の機器名と更新内容が、本体のシステム BIOS 用であることを確認してください。'
printf '%s' 'AC電源に接続した上で、この BIOS の更新を依頼しますか？ [y/N] '
IFS= read -r answer || exit 0
case "$answer" in
    y|Y) exec fwupdmgr update "$device_id" ;;
    *) printf '%s\n' '更新依頼を取り消しました。' ;;
esac
