# BIOS 更新

機種名、現在の BIOS 版、次に選べる操作を一画面に表示する Linux デスクトップアプリ。上段に機種と実機で読み取った版、下段に操作ボタンを固定する。中央で更新候補、承認内容、予約、起動後の結果、履歴をスクロールして読める。

## インストールと起動

対象環境は Ubuntu 24.04 LTS（GNOME）と Linux Mint 22 系（Cinnamon）の x86_64。配布ビルドは GTK 4 と fwupd 2.0.20 を基準にする。パッケージをダウンロードしたディレクトリで次を実行する。

```sh
sudo apt install ./mknk-bios-update_0.1.0_amd64.deb
mknk-bios-update
```

アプリ一覧の **BIOS 更新** からも一般ユーザーで起動できる。ログイン時はローカル状態を読み直し、処理中の計画やその起動で判明した結果があるときに画面を開く。閲覧専用の画面から承認へ進むときは、アプリ一覧の「更新計画を開く」を使う。`mknk-bios-update --status-only` は配布元への通信を伴わない状態確認に使える。

## 更新の操作

1. 画面上部で機種と現在版を確認する。現在の配布情報を取得できないときは、理由と前回の確認情報を表示する。
2. 候補の「更新する」でファイルを取得し、署名、機種、対象部品を照合する。承認欄で版・対象・起動操作を確認する。「今回は見送る」なら新規予約は 0 件。
3. 「この更新を承認」で、GUI が OS 標準の認可を通じて fwupd に準備を依頼する。実際の起動予約を照合すると、条件に応じて「再起動する」または「電源を切る」を選べる。「あとで」は予約を保持する。
4. 次回ログイン時に現在版と試行結果を確認する。準備依頼の応答が失われた場合は、元の記録から照合を続ける。「状態を再確認」はローカルの読み直しである。

デスクトップの終了処理と現在のセッションを照合できない場合、アプリ内の起動操作は保留になる。予約は保持される。作業を保存し、画面に表示された起動方法に従ってデスクトップの通常のメニューから再起動または電源オフを選べる。

## 対応機種と端末の設定

機種情報は Linux の DMI、更新対象は ESRT のシステム BIOS 資源と fwupd の Device ID から取得する。Linux の更新経路を確定できない機器でも、読み取れた機種と現在版、保留理由を表示する。

実機への適用には、対象の基板・BIOS・配送方式を検証した管理者所有の `/etc/mknk-bios-update.json` が必要。所有者・グループを `root:mknk-bios`、モードを `0640` にすると、配布ファイルを検証する専用ワーカーも読み取れる。実機で検証済みの機種プロファイルはこの配布物には同梱していない。プロファイルの必須項目、FMP 対象、Secure Boot と ESP の照合方法は詳細設計の「同梱のコマンドラインサンプル」に記載している。[詳細設計](mknk-bios-update-design-and-sample/Linux-BIOS-Updater-Design.md)

GUI 用の追加項目は次のとおり。

| 項目 | 用途 |
| --- | --- |
| `system_uuid_unique` | この機種で SMBIOS System UUID が個体ごとに一意と実証した場合に `true`。端末 DB に保存するのは鍵付きの照合値 |
| `power` | `minimum_battery_percent` に機種固有の最低残量、バッテリー非搭載を検証した構成では `batteryless` に `true` |
| `esp_free_bytes` | 配送方式・配布ビルドで必要な ESP 空き容量の下限（バイト） |
| `encryption` | 管理者が確認した構成。`none`、`luks`、`bitlocker`、`luks+bitlocker`、`unknown` を使う |
| `support_url`、`recovery_url` | 機種に対応するメーカー公式の更新・復旧手順の HTTPS URL。機種を照合できた場合に保留画面から開ける |
| `stable_remote_id`、`stable_metadata_uris`、`cab_base_uris` | 管理者指定の安定版ミラーの ID と、カタログおよび CAB の許可された取得先 |

一度の承認で適用するのは、署名済みカタログと照合した公開安定版一件。fwupd が中間版の連続適用を要求する場合や、独立した複数の書き込み先、未知のカプセル変換、起動先の競合がある場合には保留理由を表示する。

## ソースからビルド

リポジトリ直下で実行する。ビルド依存関係は `debian/control` に列挙している。

```sh
sudo apt install build-essential debhelper meson ninja-build pkgconf libgtk-4-dev libjson-glib-dev python3-gi gir1.2-fwupd-2.0 gir1.2-jcat-1.0 openssl dbus-daemon xvfb xauth
dpkg-buildpackage -b -us -uc
```

`.deb` はリポジトリの一つ上のディレクトリに出力される。個別にビルドとテストを行う場合は次を使う。

```sh
meson setup build/native --prefix=/usr --sysconfdir=/etc
meson compile -C build/native
meson test -C build/native --print-errorlogs
```

GTK の操作試験は Xvfb と専用の D-Bus 上で行う。実装は `src/` の一般ユーザー GUI、`backend/service.py` のシステムサービス、`backend/worker.py` の非特権ワーカーに分かれる。端末共通の計画と履歴は `/var/lib/mknk-bios-update/history.sqlite3` に保存する。[画面と状態の設計](docs/superpowers/specs/2026-11-21-linux-bios-updater-design.md)
