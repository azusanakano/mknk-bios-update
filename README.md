# BIOS 更新

機種名、現在の BIOS 版、次に選べる操作を一画面に表示する Linux デスクトップアプリ。上段に機種と実機で読み取った版、下段に操作ボタンを固定する。中央で更新候補、承認内容、予約、起動後の結果、履歴をスクロールして読める。

## コピーして起動する

Ubuntu 24.04 LTS（GNOME）と Linux Mint 22 系（Cinnamon）の x86_64 用。**`mknk-bios-update-0.1.0-x86_64.AppImage` 一つ**を対象 PC のホームフォルダーなどにコピーする。実行権限を付けたら、ファイルをダブルクリックするか次のように起動する。

```sh
chmod +x ./mknk-bios-update-0.1.0-x86_64.AppImage
./mknk-bios-update-0.1.0-x86_64.AppImage
```

通常ユーザーで開くと、機種名と現在の BIOS 版をローカルで読み取る。**更新情報を確認**を選ぶと、OS の管理者認証を通じて、その画面だけが使える一時ヘルパーを起動する。更新ファイルを fwupd に渡すのは、その後の「この更新を承認」を選んだとき。照会や承認前の準備中に画面を閉じるとヘルパーは終了する。送信許可を照合中に閉じた場合は、受け取った未使用の許可を取り消す。依頼を fwupd やデスクトップへ送った後は、結果の記録に必要な間だけ接続を維持する。

更新の予約と履歴は対象 PC に保存する。再起動後は同じ AppImage を開き、「更新情報を確認」で結果を読み直す。ポータブル版はシステムへのサービス登録やログイン時の自動起動登録を行わない。すでにパッケージ版の端末サービスがある PC では、更新操作にはアプリ一覧の「BIOS 更新」を使う。

GTK と更新の検証に使うライブラリはイメージに収録している。対象 OS の Python 3.12 を使い、実機への適用には OS 側の fwupd 2.0.20 以降、polkit（`pkexec`）、logind、UDisks などの稼働と、下記の機種別設定が必要。FUSE を利用できない環境では、同じファイルを `./mknk-bios-update-0.1.0-x86_64.AppImage --appimage-extract-and-run` で起動できる。[AppImage の起動方法](https://docs.appimage.org/user-guide/troubleshooting/fuse.html)

## パッケージ版をインストールする

アプリ一覧への登録と再ログイン時の自動確認を使う場合は、従来の Debian パッケージを使う。ダウンロードしたディレクトリで次を実行する。

```sh
sudo apt install ./mknk-bios-update_0.1.0_amd64.deb
mknk-bios-update
```

アプリ一覧の **BIOS 更新** からも一般ユーザーで起動できる。ログイン時はローカル状態を読み直し、処理中の計画やその起動で判明した結果があるときに画面を開く。閲覧専用の画面から承認へ進むときは、アプリ一覧の「更新計画を開く」を使う。`mknk-bios-update --status-only` は配布元への通信を伴わない状態確認に使える。

## 更新の操作

1. 画面上部で機種と現在版を確認する。現在の配布情報を取得できないときは、理由と前回の確認情報を表示する。
2. 候補の「更新する」でファイルを取得し、署名、機種、対象部品を照合する。承認欄で版・対象・起動操作を確認する。「今回は見送る」なら新規予約は 0 件。
3. 「この更新を承認」で、GUI が OS 標準の認可を通じて fwupd に準備を依頼する。実際の起動予約を照合すると、条件に応じて「再起動する」または「電源を切る」を選べる。アプリ内で実行を確認すると、デスクトップに終了を依頼する。「あとで」や確認の取り消しで予約は保持される。
4. 次回ログイン時に現在版と試行結果を確認する。準備依頼の応答が失われた場合は、元の記録から照合を続ける。「状態を再確認」はローカルの読み直しである。

別の利用者が承認した未送信の計画は「管理者として承認を解除」から解除できる。管理者認証と予約の再照合を済ませたら、現在の利用者が新しい計画を確認して承認する。

デスクトップの終了処理と現在のセッションを照合できない場合、アプリ内の起動操作は保留になる。予約は保持される。作業を保存し、画面に表示された起動方法に従ってデスクトップの通常のメニューから再起動または電源オフを選べる。

## 対応機種と端末の設定

機種情報は Linux の DMI、更新対象は ESRT のシステム BIOS 資源と fwupd の Device ID から取得する。Linux の更新経路を確定できない機器でも、読み取れた機種と現在版、保留理由を表示する。

実機への適用には、対象の基板・BIOS・配送方式を検証した管理者所有の `/etc/mknk-bios-update.json` が必要。AppImage では root のヘルパーが設定を読み取る。パッケージ版では所有者・グループを `root:mknk-bios`、モードを `0640` にすると専用ワーカーも読み取れる。実機で検証済みの機種プロファイルはこの配布物には同梱していない。プロファイルの必須項目、FMP 対象、Secure Boot と ESP の照合方法は詳細設計の「同梱のコマンドラインサンプル」に記載している。[詳細設計](mknk-bios-update-design-and-sample/Linux-BIOS-Updater-Design.md)

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
sudo apt install build-essential debhelper meson ninja-build pkgconf libgtk-4-dev libjson-glib-dev python3-gi gir1.2-fwupd-2.0 gir1.2-jcat-1.0 gir1.2-atspi-2.0 openssl dbus-daemon xvfb xauth python3-xlib xdotool
dpkg-buildpackage -b -us -uc
```

`.deb` はリポジトリの一つ上のディレクトリに出力される。個別にビルドとテストを行う場合は次を使う。

```sh
meson setup build/native --prefix=/usr --sysconfdir=/etc
meson compile -C build/native
meson test -C build/native --print-errorlogs
```

GTK の操作試験は Xvfb と専用の D-Bus 上で行う。実装は `src/` の一般ユーザー GUI、`backend/service.py` のシステムサービス、`backend/worker.py` の非特権ワーカーに分かれる。端末共通の計画と履歴は `/var/lib/mknk-bios-update/history.sqlite3` に保存する。[画面と状態の設計](docs/superpowers/specs/2026-11-21-linux-bios-updater-design.md)

### AppImage を作る

Ubuntu 24.04 amd64 のビルド環境で、上記に加えて次を実行する。`portable/build_image.py` は公式の Type 2 ランタイムの SHA-256 を照合し、単一の実行ファイルを `dist/` に生成する。収録したライブラリの配布元パッケージとライセンスは、イメージ内の `usr/share/doc/mknk-bios-update/third-party/` にある。

```sh
sudo apt install gobject-introspection squashfs-tools adwaita-icon-theme librsvg2-bin libarchive13t64
mkdir -p build
curl -fL -o build/runtime-x86_64 https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64
curl -fL -o build/runtime-x86_64.LICENSE https://raw.githubusercontent.com/AppImage/type2-runtime/fedfad51acc2860b2916a1eef32ba4a500ff31ef/LICENSE
/usr/bin/python3 portable/build_image.py --runtime build/runtime-x86_64
```

この配布ビルドのランタイムは `fedfad51acc2860b2916a1eef32ba4a500ff31ef`。上流の continuous 配布が更新された場合はこの版のランタイムを用意するか、採用する新版の配布元ハッシュとライセンスを確認し、`--runtime-sha256` と `--runtime-license` に指定する。[AppImage 公式ランタイム](https://github.com/AppImage/type2-runtime)
