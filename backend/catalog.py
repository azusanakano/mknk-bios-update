"""Read-only fwupd queries and authenticated download processing in a disposable worker."""
import base64
import configparser
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import BaseHandler, HTTPRedirectHandler, build_opener

from firmware_api import fw

TRUST_DIRECTORIES = ("/etc/pki/fwupd", "/etc/pki/fwupd-metadata")


def fingerprint(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def remote_fingerprint(remote):
    """Bind import to the enabled source, its cache paths and distribution policy."""
    keys = ("Id", "Kind", "Enabled", *fw.REMOTE_URI_FIELDS, "FilenameSource", "FilenameCache",
            "FilenameCacheSig", "ApprovalRequired", "Flags", "OrderBefore", "OrderAfter", "Priority")
    identity = {key: remote.get(key) for key in keys}
    identity["authenticated"] = bool(remote.get("Username") or remote.get("Password"))
    return fingerprint(identity)


def read_trust_policy():
    """Called by the service before dropping uid. Do not export other daemon settings."""
    paths = ("/etc/fwupd/fwupd.conf", "/var/etc/fwupd/fwupd.conf")
    for path in paths:
        config = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            with open(path, encoding="utf-8") as stream:
                config.read_file(stream)
        except FileNotFoundError:
            continue
        # A stricter setting in either file always wins.
        if config.getboolean("fwupd", "OnlyTrustPostQuantumSignatures", fallback=False):
            return "1"
    return "0"


class Session:
    def __init__(self):
        self.Fwupd, self.GLib = fw.fwupd_bindings()
        from gi.repository import Gio
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.client = self.Fwupd.Client.new()
        if not self.client.set_feature_flags(self.Fwupd.FeatureFlags.NONE, None):
            raise fw.Hold("fwupdで画面の機能を登録できません。")
        self.owner = self.current_owner()
        self.version = self.client.get_daemon_version()
        if not self.version:
            raise fw.Hold("fwupdの版を確認できません。")

    def current_owner(self):
        return self.bus.call_sync(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetNameOwner", self.GLib.Variant("(s)", (fw.FWUPD_ID,)),
            self.GLib.VariantType.new("(s)"), 0, 5000, None).unpack()[0]

    def rows(self, operation, *args):
        try:
            items = getattr(self.client, operation)(*args, None)
        except self.GLib.Error as exc:
            if (operation in ("get_upgrades", "get_releases", "search")
                    and exc.domain == "FwupdError" and exc.code == self.Fwupd.Error.NOTHING_TO_DO):
                return []
            raise fw.Hold("fwupdから機器・配布情報を取得できません。") from exc
        rows = []
        for item in items:
            row = json.loads(item.to_json_string(self.Fwupd.CodecFlags.NONE))
            if operation == "get_devices":
                row["CompositeId"] = item.get_composite_id()
            rows.append(row)
        return rows

    def remote(self, settings):
        identifier = settings.get("stable_remote_id", fw.REMOTE)
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier):
            raise fw.Hold("安定版配布元の識別子を確認できません。")
        remotes = self.rows("get_remotes")
        remote = fw.stable_remote(settings, remotes=remotes, remote_id=identifier, allow_credentials=True)
        if ((remote.get("Username") or remote.get("Password"))
                and remote["MetadataUri"] not in settings.get("stable_metadata_uris", [])):
            raise fw.Hold("認証用ミラーの配布元を管理者の設定に照合できません。")
        return remote

    def native_remote(self, remote):
        item = self.client.get_remote_by_id(remote["Id"], None)
        if json.loads(item.to_json_string(self.Fwupd.CodecFlags.NONE)) != remote:
            raise fw.Hold("照会中に配布元の設定が変化しました。再確認してください。")
        return item

    def policy(self, remote):
        def checksums(items):
            if not isinstance(items, (list, tuple)) or not all(isinstance(x, str) for x in items):
                raise fw.Hold("管理者の配布制限を確認できません。")
            return {x.lower() for x in items}
        approved = (checksums(self.client.get_approved_firmware(None))
                    if remote.get("ApprovalRequired") else None)
        return approved, checksums(self.client.get_blocked_firmware(None))


def signature_json(signature):
    with gzip.GzipFile(fileobj=io.BytesIO(signature)) as stream:
        decoded = stream.read(4 * fw.METADATA_SIG_LIMIT + 1)
    if len(decoded) > 4 * fw.METADATA_SIG_LIMIT:
        raise fw.Hold("展開したカタログ署名のサイズが上限を超えています。")
    return decoded.decode()


def signing_time(metadata, signature):
    import gi
    gi.require_version("Jcat", "1.0")
    from gi.repository import GLib, Jcat

    catalog = Jcat.File.new()
    if not catalog.import_json(signature_json(signature), Jcat.ImportFlags.NONE):
        raise fw.Hold("カタログ署名を読み取れません。")
    item = catalog.get_item_default()
    flags = Jcat.VerifyFlags.REQUIRE_CHECKSUM | Jcat.VerifyFlags.REQUIRE_SIGNATURE
    pq = os.environ.get("MKNK_FWUPD_ONLY_PQ")
    if pq is None:
        pq = read_trust_policy()
    if pq == "1":
        flags |= Jcat.VerifyFlags.ONLY_PQ
    elif pq != "0":
        raise fw.Hold("fwupdの署名検証設定を確認できません。")
    with tempfile.TemporaryDirectory() as keyring:
        context = Jcat.Context.new()
        context.set_keyring_path(keyring)
        for kind in (Jcat.BlobKind.SHA256, Jcat.BlobKind.SHA512, Jcat.BlobKind.PKCS7, Jcat.BlobKind.GPG):
            context.blob_kind_allow(kind)
        for directory in TRUST_DIRECTORIES:
            context.add_public_keys(directory)
        results = context.verify_item(GLib.Bytes.new(metadata), item, flags)
        timestamp = max((r.get_timestamp() for r in results if r.get_method() == Jcat.BlobMethod.SIGNATURE),
                        default=0)
    # The GnuTLS JCat backend uses 1 when the PKCS#7 signed time is absent.
    if timestamp <= 1:
        raise fw.Hold("カタログの検証済み署名日時を確認できません。")
    return timestamp


def authenticated(metadata, signature, guids):
    try:
        timestamp = signing_time(metadata, signature)
    except Exception as exc:
        raise fw.Hold("OSの信頼鍵と署名ポリシーで配布カタログを検証できません。") from exc
    if not metadata.startswith((b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")):
        raise fw.Hold("配布カタログの圧縮形式を確認できません。")
    digest = hashlib.sha256()
    components = fw.read_catalog_components(metadata, guids, digest=digest)
    identity = dict(signed_timestamp=timestamp, download_signed_timestamp=timestamp, catalog_sha256=digest.hexdigest(),
                    compressed_sha256=hashlib.sha256(metadata).hexdigest(),
                    signature_sha256=hashlib.sha256(signature).hexdigest(),
                    compressed_size=len(metadata), signature_size=len(signature))
    return components, identity


def protected_uri(uri):
    """Strip userinfo generated by libfwupd before validating the destination."""
    parsed = urlsplit(uri)
    clean = urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, parsed.query, parsed.fragment))
    fw.https_origin_path(clean)
    return clean


def metadata_uri_allowed(uri, base):
    host, port, path = fw.https_origin_path(uri)
    base_host, base_port, base_path = fw.https_origin_path(base)
    if (host, port) != (base_host, base_port):
        return False
    parent, name = path.rsplit("/", 1)
    directory, _ = base_path.rsplit("/", 1)
    return path == base_path or (parent == directory and
           re.fullmatch(r"firmware-[0-9]{1,16}-stable\.xml\.(?:xz|zst)", name) is not None)


def with_auth(uri, remote):
    return uri.rstrip("/") + "/auth" if ((remote.get("Username") or remote.get("Password"))
                                         and not uri.endswith("/auth")) else uri


class CatalogRedirect(fw.CabRedirectHandler):
    """Use the bounded, body-closing redirect implementation for metadata as well."""
    def __init__(self, allowed):
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fw.https_origin_path(newurl)
        if newurl not in self.allowed:
            raise fw.Hold("配布元の転送先は、このファイルの許可範囲外です。")
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)


class ResourceAuth(BaseHandler):
    """Attach mirror credentials only to explicit resource URLs. urllib does not forward this header."""
    def __init__(self, remote, allowed):
        self.allowed = allowed
        self.header = None
        if remote.get("Username") or remote.get("Password"):
            user = remote.get("Username") or ""
            password = remote.get("Password") or ""
            if ":" in user:
                raise fw.Hold("ミラーの認証設定を解釈できません。")
            self.header = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")

    def https_request(self, req):
        if self.header and req.full_url in self.allowed:
            req.add_unredirected_header("Authorization", self.header)
        return req


def download(remote, settings, session):
    uri = remote["MetadataUri"]
    native = session.native_remote(remote)
    sig_uri = native.get_metadata_uri_sig()
    if sig_uri != uri + ".jcat" or remote.get("MetadataUriSig") != sig_uri:
        raise fw.Hold("配布元のカタログと署名の取得先を確認できません。")
    endpoints = {uri}
    for endpoint in settings.get("stable_metadata_uris", []):
        host, _, _ = fw.https_origin_path(endpoint)
        if host not in ("fwupd.org", "cdn.fwupd.org") or endpoint in fw.LVFS_METADATA_URIS:
            endpoints.add(endpoint)
    try:
        sig_uri = with_auth(sig_uri, remote)
        allowed_sigs = {u + ".jcat" for u in endpoints} | {sig_uri}
        opener = build_opener(CatalogRedirect(allowed_sigs), ResourceAuth(remote, {sig_uri}))
        signature = fw.download_catalog_file(opener, sig_uri, fw.METADATA_SIG_LIMIT)
        signature_json(signature)  # bound expansion before the native parser consumes it
        _, GLib = fw.fwupd_bindings()
        if not native.load_signature_bytes(GLib.Bytes.new(signature)):
            raise fw.Hold("カタログの署名対象ファイル名を確認できません。")
        uri = native.get_metadata_uri()
        if not metadata_uri_allowed(uri, remote["MetadataUri"]):
            raise fw.Hold("カタログ署名が示すファイルが安定版の取得範囲外です。")
        uri = with_auth(uri, remote)
        opener = build_opener(CatalogRedirect(endpoints | {uri}), ResourceAuth(remote, {uri}))
        metadata = fw.download_catalog_file(opener, uri, fw.METADATA_LIMIT)
    except Exception as exc:
        raise fw.Hold("配布元からカタログと署名を取得できません。通信状態と配布元を確認してください。") from exc
    return metadata, signature


def cache_pair(remote):
    filenames = (remote.get("FilenameCache"), remote.get("FilenameCacheSig"))
    if not all(isinstance(p, str) and Path(p).is_absolute() for p in filenames):
        raise fw.Hold("fwupdの安定版キャッシュの場所を確認できません。")
    contents = []
    for name, limit in zip(filenames, (fw.METADATA_LIMIT, fw.METADATA_SIG_LIMIT)):
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise fw.Hold("fwupdのキャッシュの所有者またはアクセス権を確認できません。")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise fw.Hold("fwupdのキャッシュのサイズが上限を超えています。")
            contents.append(data)
    return tuple(contents)


class NeedsRefresh(fw.Hold):
    pass


def compare_cache(remote, pair, info, report):
    try:
        cached = cache_pair(remote)
    except FileNotFoundError:
        return None
    if cached == pair:
        return cached
    try:
        _, old = authenticated(*cached, set())
    except fw.Hold:
        # The service's independent durable high-water mark still gates replacement.
        return None
    if old["catalog_sha256"] != info["catalog_sha256"]:
        if old["signed_timestamp"] >= info["signed_timestamp"]:
            report.update(old)
            raise fw.Hold("配布元の署名世代が現在のキャッシュと競合しています。")
        return None
    # For identical expanded bytes the most recent verified signature is a rollback floor.
    report["signed_timestamp"] = max(info["signed_timestamp"], old["signed_timestamp"])
    return cached


def sealed_size(stream, limit):
    import fcntl
    fd = stream.fileno()
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals != seals:
        raise fw.Hold("配布物を変更不可の内容として確認できません。")
    size = os.fstat(fd).st_size
    if not 0 < size <= limit:
        raise fw.Hold("固定した配布ファイルの長さを確認できません。")
    return size


def write_sealed(stream, data):
    import fcntl
    stream.seek(0)
    stream.truncate()
    stream.write(data)
    stream.flush()
    fd = stream.fileno()
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    if sealed_size(stream, len(data)) != len(data):
        raise fw.Hold("固定した配布ファイルの長さが一致しません。")
    stream.seek(0)
    if hashlib.file_digest(stream, "sha256").digest() != hashlib.sha256(data).digest():
        raise fw.Hold("固定した配布ファイルの内容が一致しません。")
    stream.seek(0)


def fetch_release(release, remote, cabinet, settings, size, session):
    native = session.native_remote(remote)
    bases = fw.cab_bases(settings)
    configured = [fw.https_origin_path(p) for p in settings.get("cab_base_uris", [])]
    mirror_origin = fw.https_origin_path(remote["MetadataUri"])[:2]
    locations = []
    authenticated_urls = set()
    for location in fw.strings(release, "Locations"):
        try:
            # A release URI itself may never provide credentials or query data.
            input_uri = urljoin(remote["MetadataUri"], location)
            fw.https_origin_path(input_uri)
            uri = protected_uri(native.build_firmware_uri(input_uri))
            fw.require_cab_url(uri, bases)
        except (fw.Hold, ValueError):
            continue
        locations.append(uri)
        h, port, path = fw.https_origin_path(uri)
        if ((h, port) == mirror_origin and path.endswith("/auth")
                and any((h, port) == (bh, bp) and path.startswith(prefix) for bh, bp, prefix in configured)):
            authenticated_urls.add(uri)
    opener = build_opener(fw.CabRedirectHandler(bases), ResourceAuth(remote, authenticated_urls))
    return fw.fetch_cab(dict(release, Locations=locations), remote, cabinet, settings,
                        download_size=size, opener=opener)


def verified_payload(cabinet, mode, release, remote, result, device, devices, guid, profile, session):
    if mode == "prepare":
        fetch_release(release, remote, cabinet, profile, result.download_size, session)
    size = sealed_size(cabinet, fw.CAB_DOWNLOAD_LIMIT)
    if result.download_size is not None and size != result.download_size:
        raise fw.Hold("固定した配布ファイルと署名サイズが一致しません。")
    path = fw.cabinet_path(cabinet.fileno())
    fw.verify_cabinet_hashes(cabinet, fw.release_hashes(release) | result.hashes)
    actual = {}
    for algorithm in ("sha1", "sha256", "sha512"):
        cabinet.seek(0)
        actual[algorithm] = hashlib.file_digest(cabinet, algorithm).hexdigest()
    cabinet.seek(0)
    parts = session.rows("get_details", path)
    scope, payload, raw = fw.verify_cab(path, release, guid, device, devices, profile,
                                        parts=parts, include_payload=True)
    # fwupd 2.0 leaves FMP and matching ESRT headers intact on the supported
    # NVRAM and standard capsule-on-disk paths. Other inputs can require fixup.
    if not payload.startswith((fw.FMP_CAPSULE, uuid.UUID(guid).bytes_le)):
        raise fw.Hold("配送時に変更されるメーカー形式のカプセルを予約内容と照合できません。")
    fw.capsule_header_size(payload, 0)
    target_raw = None
    if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", raw):
        number = int(raw, 16 if raw.lower().startswith("0x") else 10)
        if 0 < number <= 0xffffffff and fw.esrt_version(raw, device["VersionFormat"]) == release["Version"]:
            target_raw = number
    plan = dict(checksum=actual["sha256"], cab_sha512=actual["sha512"], payload_sha256=hashlib.sha256(payload).hexdigest(),
                payload_size=len(payload), scope=scope, target_raw=target_raw)
    return plan, set(actual.values())


def signed_entries(components, indexed, remote_id, fmt):
    for row in indexed:
        if row.get("RemoteId") != remote_id or not row.get("AppstreamId") or not row.get("Version"):
            continue
        for component in components:
            if (component.findtext("id") != row["AppstreamId"]
                    or (component.findtext("branch") or "default") != (row.get("Branch") or "default")):
                continue
            for entry in component.findall("releases/release"):
                if (fw.release_version_matches(entry.get("version"), row["Version"], fmt)
                        and fw.same_cab(fw.strong_hashes(fw.strings(row, "Checksum")),
                                        fw.strong_hashes(fw.catalog_cab(entry)[0]))):
                    yield row, entry


def release_notes(entry):
    descriptions = entry.findall("description")
    language = "{http://www.w3.org/XML/1998/namespace}lang"
    selected = next((node for node in descriptions if node.get(language, "").startswith("ja")), None)
    if selected is None:
        selected = next((node for node in descriptions if not node.get(language)), None)
    text = "" if selected is None else " ".join(fw.visible(" ".join(selected.itertext())).split())[:4096]
    return text or "配布元による変更内容の記載はありません。"


def device_identity(devices):
    # Include peers used in signed firmware requirements and composite scope.
    fields = ("DeviceId", "CompositeId", "Plugin", "Version", "VersionFormat", "Branch",
              "Flags", "Problems", "Guid", "VendorIds", "Protocols", "UpdateState", "UpdateError")
    return sorted(fingerprint([d.get(key) for key in fields]) for d in devices)


def evaluate(mode, guid, cabinet, session, settings, remote, components, report, device, devices):
    flags = set(fw.strings(device, "Flags"))
    if "emulated" in flags:
        raise fw.Hold("この機器では実機の BIOS を確認できません。")
    if "install-all-releases" in flags:
        raise fw.Hold("この BIOS は中間版を順に適用する必要があります。機種別の更新手順を確認してください。")
    if fw.strings(device, "Problems") or device.get("UpdateError") or "updatable" not in flags:
        raise fw.Hold("fwupdが機器の更新を保留しています。 " + fw.visible(device.get("UpdateError") or
                          "、".join(fw.strings(device, "Problems"))))
    identifier = device["DeviceId"]
    remote_id = remote["Id"]
    upgrades = session.rows("get_upgrades", identifier)
    release = fw.candidate(device, releases=upgrades, remote_id=remote_id)
    policy = session.policy(remote)
    result = fw.require_catalog_release(components, device, devices, guid, release, remote,
                                        daemon_version=session.version, client_features=(), policy=policy)
    if not release and (not result.model_listed or result.unavailable):
        raise fw.Hold(result.unavailable or "この安定版配布元で機種の掲載を確認できません。")
    fmt = device.get("VersionFormat")
    if not fmt or fmt == "unknown":
        raise fw.Hold("実機BIOSの版の形式を確認できません。")
    indexed = session.rows("get_releases", identifier)
    if not release:
        if not any(signed_entries(components, indexed, remote_id, fmt)):
            found = False
            for component in components:
                app_id = component.findtext("id")
                if app_id and any(signed_entries([component], session.rows("search", app_id), remote_id, fmt)):
                    found = True
                    break
            if not found:
                raise NeedsRefresh("配布元とfwupdの索引を照合できません。")
        return dict(state="current", detail="この配布元に適用可能な新版はありません。")
    if fw.version_key(release["Version"], fmt) <= fw.version_key(device["Version"], fmt):
        raise fw.Hold("現在のBIOSより新しい安定版を確認できません。")
    selected = [r for r in indexed if r.get("RemoteId") == remote_id
                and r.get("AppstreamId") == release["AppstreamId"] and r.get("Version") == release["Version"]
                and (r.get("Branch") or "default") == (device.get("Branch") or "default")
                and fw.same_cab(fw.release_hashes(release), fw.strong_hashes(fw.strings(r, "Checksum")))]
    if not selected:
        raise NeedsRefresh("現在の安定版候補をfwupdの索引で確認できません。")
    if any({"blocked-approval", "blocked-version", "is-alternate-branch", "is-downgrade"}
           .intersection(fw.strings(r, "Flags")) for r in selected):
        raise fw.Hold("fwupdの配布条件により候補の適用が保留されています。")
    entry = next((e for _, e in signed_entries(components, [release], remote_id, fmt)), None)
    if entry is None:
        raise NeedsRefresh("配布元と候補の版・配布ファイルを照合できません。")
    changes = release_notes(entry)
    shutdown = "needs-shutdown" in (flags | set(fw.strings(release, "Flags")))
    plan = dict(state="available", detail="この機種に適用できる更新があります。", target=release["Version"],
                changes=changes, shutdown=shutdown, version_format=fmt, appstream_id=release["AppstreamId"])
    token_input = [identifier, guid, sorted(fw.strings(device, "Guid")), device["Version"], fmt,
                   device.get("Branch"), device.get("CompositeId"), release["AppstreamId"], plan["target"],
                   result.hashes, report["catalog_sha256"], remote_id, report["remote_fingerprint"],
                   report["settings_fingerprint"], session.owner, session.version, shutdown]
    plan["token"] = fingerprint(token_input)
    if mode != "check":
        profile = fw.support_profile(settings, guid, device)
        prepared, actual = verified_payload(cabinet, mode, release, remote, result, device, devices,
                                           guid, profile, session)
        # A candidate can disappear while the user waits for a large download.
        latest = fw.candidate(device, releases=session.rows("get_upgrades", identifier), remote_id=remote_id)
        if (not latest or any(latest.get(k) != release.get(k) for k in ("AppstreamId", "Version", "Branch", "Flags"))
                or fw.release_hashes(latest) != fw.release_hashes(release)):
            raise fw.Hold("配布ファイルの照合中に更新候補が変化しました。")
        fw.require_catalog_release(components, device, devices, guid, release, remote,
                                   daemon_version=session.version, verified_hashes=actual,
                                   client_features=(), policy=session.policy(remote))
        plan.update(prepared)
    return plan


def run(mode, guid, cabinet=None, metadata=None, signature=None):
    report = {"state": "hold", "detail": "", "guid": guid, "checked": ""}
    try:
        if mode not in ("check", "prepare", "revalidate", "metadata") or not fw.GUID_TEXT.fullmatch(guid):
            raise fw.Hold("配布情報の照会対象を特定できません。")
        session = Session()
        settings = fw.read_settings()
        remote = session.remote(settings)
        guid, device, devices = fw.inventory(guid, devices=session.rows("get_devices"))
        if sum(d.get("DeviceId") == device["DeviceId"] for d in devices) != 1:
            raise fw.Hold("実機のデバイス識別子が重複しています。")
        source = ("LVFS 安定版" if remote["MetadataUri"] in fw.LVFS_METADATA_URIS
                  else "安定版ミラー " + fw.https_origin_path(remote["MetadataUri"])[0])
        report.update(device=device["DeviceId"], current=device["Version"], source=source,
                      daemon_owner=session.owner, remote_id=remote["Id"], settings_fingerprint=fingerprint(settings),
                      remote_fingerprint=remote_fingerprint(remote))
        pair = download(remote, settings, session)
        guids = {g.lower() for g in fw.strings(device, "Guid")} | {guid}
        components, info = authenticated(*pair, guids)
        report.update(info)
        cached = compare_cache(remote, pair, info, report)
        if mode == "metadata":
            write_sealed(metadata, pair[0])
            write_sealed(signature, pair[1])
            plan = dict(state="metadata", detail="配布情報の署名を確認しました。")
        else:
            if cached is None:
                raise NeedsRefresh("安定版の配布情報をfwupdに取り込む必要があります。")
            plan = evaluate(mode, guid, cabinet, session, settings, remote, components, report, device, devices)
        if (session.current_owner() != session.owner or settings != fw.read_settings()
                or remote != session.remote(settings)):
            raise fw.Hold("照会中にfwupdまたは配布設定が変化しました。再確認してください。")
        if cached is not None and cache_pair(remote) != cached:
            raise fw.Hold("照会中にfwupdの配布情報が変化しました。再確認してください。")
        if mode != "metadata" and device_identity(devices) != device_identity(session.rows("get_devices")):
            raise fw.Hold("照会中に機器構成または版が変化しました。再確認してください。")
        report.update(plan, checked=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    except NeedsRefresh as exc:
        report.update(detail=str(exc), refresh_required=True)
    except (fw.Hold, fw.Error) as exc:
        report["detail"] = fw.visible(str(exc))[:512]
    except Exception:
        # Raw exceptions can contain network credentials or private machine identifiers.
        report["detail"] = "配布情報・署名・更新対象を読み取れません。fwupdと必要なライブラリを確認してください。"
    return report


def query(mode: str, guid: str, cabinet=None) -> dict:
    return run(mode, guid, cabinet=cabinet)


def fetch_metadata(guid: str, metadata, signature) -> dict:
    return run("metadata", guid, metadata=metadata, signature=signature)
