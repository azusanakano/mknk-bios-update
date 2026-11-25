"""Machine-wide update receipts. Every permission is committed before it leaves the service."""
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Conflict(Exception):
    """An observation or a concurrent operation prevents this action."""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


OPERATION_TABLE = """CREATE TABLE IF NOT EXISTS operation (
    id TEXT PRIMARY KEY, boot TEXT NOT NULL, machine TEXT NOT NULL,
    plan TEXT NOT NULL, sender TEXT NOT NULL, daemon TEXT NOT NULL, bus TEXT NOT NULL,
    issued TEXT NOT NULL, receipt TEXT NOT NULL DEFAULT 'unknown',
    active INTEGER NOT NULL DEFAULT 1, outcome TEXT, observed TEXT, ended TEXT,
    power_id TEXT, power_sender TEXT, power_bus TEXT, observed_boot TEXT, power_boot TEXT)"""


class Journal:
    def __init__(self, path):
        self.path = path
        with self.transaction() as db:
            db.execute(OPERATION_TABLE)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(operation)")}
            if "observed_boot" not in columns:
                db.execute("ALTER TABLE operation ADD COLUMN observed_boot TEXT")
            if "power_boot" not in columns:
                db.execute("ALTER TABLE operation ADD COLUMN power_boot TEXT")
            if any(row["origin"] == "u" for row in db.execute("PRAGMA index_list(operation)")):
                # SQLite cannot remove the original inline UNIQUE on boot in place.
                db.execute("ALTER TABLE operation RENAME TO operation_with_unique_boot")
                db.execute(OPERATION_TABLE)
                columns = ",".join(row["name"] for row in db.execute("PRAGMA table_info(operation)"))
                db.execute(f"INSERT INTO operation (rowid,{columns}) "
                           f"SELECT rowid,{columns} FROM operation_with_unique_boot")
                db.execute("DROP TABLE operation_with_unique_boot")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS single_pending ON operation(active) WHERE active=1")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS single_issue_per_boot ON operation(boot)
                          WHERE outcome IS NOT 'rejected'""")
            db.execute("CREATE TABLE IF NOT EXISTS setting (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS approval (slot INTEGER PRIMARY KEY CHECK(slot=1), id TEXT, plan TEXT)")
            db.execute("INSERT OR IGNORE INTO setting VALUES ('identity-key', ?)", (secrets.token_hex(32),))

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=8)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def machine_key(self, value):
        if not value:
            return ""
        with self.transaction() as db:
            key = bytes.fromhex(db.execute("SELECT value FROM setting WHERE name='identity-key'").fetchone()[0])
        return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def unpack(row):
        if row is None:
            return None
        obj = dict(row)
        plan = json.loads(obj.pop("plan"))
        return {**plan, **obj}

    def active(self):
        with self.transaction() as db:
            return self.unpack(db.execute("SELECT * FROM operation WHERE active=1").fetchone())

    def last(self, machine, boot):
        with self.transaction() as db:
            return self.unpack(db.execute(
                """SELECT * FROM operation WHERE (machine=? AND machine!='') OR boot=?
                   OR (outcome='unattributed' AND observed_boot=?) ORDER BY rowid DESC LIMIT 1""",
                (machine, boot, boot)).fetchone())

    def approval(self):
        with self.transaction() as db:
            row = db.execute("SELECT plan FROM approval WHERE slot=1").fetchone()
            return json.loads(row[0]) if row else None

    def approve(self, plan):
        with self.transaction() as db:
            row = db.execute("SELECT id FROM approval").fetchone()
            if (row and row["id"] != plan["id"]) or db.execute("SELECT 1 FROM operation WHERE active=1").fetchone():
                raise Conflict("別の計画の承認または送信を確認中です。")
            db.execute("INSERT OR IGNORE INTO approval VALUES (1,?,?)", (plan["id"], json.dumps(plan)))

    def cancel_approval(self, plan_id):
        with self.transaction() as db:
            db.execute("DELETE FROM approval WHERE id=?", (plan_id,))

    def issue(self, plan, sender, daemon, bus, *, from_approval=False):
        try:
            with self.transaction() as db:
                if from_approval and not db.execute("DELETE FROM approval WHERE id=?", (plan["id"],)).rowcount:
                    raise Conflict("準備前の承認が取り消されました。")
                db.execute("""INSERT INTO operation(id,boot,machine,plan,sender,daemon,bus,issued)
                              VALUES (?,?,?,?,?,?,?,?)""",
                           (plan["id"], plan["boot"], plan["machine"], json.dumps(plan), sender, daemon, bus, now()))
        except sqlite3.IntegrityError as exc:
            raise Conflict("更新の依頼記録があります。状態を再確認してください。") from exc
        except sqlite3.Error as exc:
            # A failed write may have rolled back or committed before failing.
            # Allow the caller to remove its marker only if the journal proves no issue exists.
            try:
                uri = Path(self.path).resolve().as_uri() + "?mode=ro"
                with closing(sqlite3.connect(uri, uri=True, timeout=8)) as db:
                    recorded = db.execute("SELECT 1 FROM operation WHERE id=?", (plan["id"],)).fetchone()
            except sqlite3.Error:
                raise exc
            if recorded is None:
                raise Conflict("更新の依頼記録を保存できませんでした。保存先を確認してください。") from exc
            raise

    def report(self, op, sender, bus, accepted):
        with self.transaction() as db:
            changed = db.execute("""UPDATE operation SET receipt=CASE WHEN receipt='rejected' THEN receipt
                                        WHEN ? THEN 'accepted'
                                        WHEN receipt='unknown' THEN 'unconfirmed' ELSE receipt END
                                    WHERE id=? AND sender=? AND bus=?""", (bool(accepted), op, sender, bus))
            if not changed.rowcount:
                raise Conflict("更新依頼と応答元の接続が一致しません。")

    def report_rejection(self, op, sender, bus):
        with self.transaction() as db:
            changed = db.execute("""UPDATE operation SET receipt='rejected' WHERE id=? AND sender=? AND bus=?
                                    AND active=1 AND receipt IN ('unknown','unconfirmed','rejected')""",
                                 (op, sender, bus))
            if not changed.rowcount:
                raise Conflict("未送達・配置前の拒否を記録できる応答元と状態を確認できません。")

    def decline_authorization(self, op, sender, bus, release_claim):
        # Only the GUI that received this permit can acknowledge it stopped before Install.
        with self.transaction() as db:
            row = db.execute("""SELECT * FROM operation WHERE id=? AND sender=? AND bus=?
                                AND active=1 AND receipt='unknown' AND power_id IS NULL""",
                             (op, sender, bus)).fetchone()
            if row is None:
                raise Conflict("未送信の許可を取り消せる接続・状態ではありません。")
            release_claim(self.unpack(row))
            db.execute("DELETE FROM operation WHERE id=?", (op,))

    def finish(self, op, outcome, current, *, observed_boot=None, release_claim=None):
        with self.transaction() as db:
            if outcome == "rejected":
                row = db.execute("SELECT * FROM operation WHERE id=? AND active=1 AND receipt='rejected'",
                                 (op,)).fetchone()
                if row is None:
                    raise Conflict("配置前の拒否を確認できません。")
                if release_claim is not None:
                    release_claim(self.unpack(row))
            db.execute("""UPDATE operation SET active=0,outcome=?,observed=?,ended=?,observed_boot=?
                          WHERE id=? AND active=1""", (outcome, current, now(), observed_boot, op))

    def history(self, machine, boot=""):
        with self.transaction() as db:
            rows = db.execute("""SELECT * FROM operation WHERE (machine=? AND machine!='') OR boot=?
                                 OR (outcome='unattributed' AND observed_boot=?)
                                 ORDER BY rowid DESC LIMIT 20""", (machine, boot, boot)).fetchall()
        outcomes = {"installed": "目標版を確認", "unapplied": "目標版に未到達", "failed": "試行失敗",
                    "unattributed": "旧計画への帰属は未確認", "rejected": "配置なしを確認"}
        receipts = {"accepted": "受付済み", "rejected": "未送達または配置前に拒否"}
        lines = []
        for row in rows:
            p = self.unpack(row)
            receipt = receipts.get(p["receipt"], "受付未確定")
            result = outcomes.get(p["outcome"], "結果を照合中")
            lines.append(f"{p['issued']}　{p['current']} → {p['target']}　{receipt}　{result}"
                         + (f"（実機 {p['observed']}）" if p["observed"] else ""))
        return "\n".join(lines)

    def bind_legacy_power_boot(self, op, request, boot):
        # Historical records did not record the power request's boot. Keep the
        # exclusion through the first known boot until another boot is observed.
        with self.transaction() as db:
            db.execute("""UPDATE operation SET power_boot=?
                          WHERE id=? AND active=1 AND power_id=? AND power_boot IS NULL""",
                       (boot, op, request))

    def power(self, op, sender, bus, boot):
        if not boot:
            raise Conflict("今回の起動を確認できません。")
        request = str(uuid.uuid4())
        with self.transaction() as db:
            changed = db.execute("""UPDATE operation SET power_id=?,power_sender=?,power_bus=?,power_boot=?
                                    WHERE id=? AND active=1 AND (power_id IS NULL OR power_boot<>?)""",
                                 (request, sender, bus, boot, op, boot))
            if not changed.rowcount:
                raise Conflict("起動操作はすでに処理中か、予約が変わりました。状態を再確認してください。")
        return request

    def power_reply(self, request, sender, bus, cancelled):
        with self.transaction() as db:
            args = (request, sender, bus)
            where = " WHERE power_id=? AND power_sender=? AND power_bus=? AND active=1"
            if not db.execute("SELECT id FROM operation" + where, args).fetchone():
                raise Conflict("電源操作の要求元を確認できません。")
            if cancelled:
                db.execute("UPDATE operation SET power_id=NULL,power_sender=NULL,power_bus=NULL,power_boot=NULL"
                           + where, args)

    def catalog_generation(self, stamp, digest):
        if type(stamp) is not int or stamp <= 0 or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Conflict("配布情報の署名時刻またはハッシュを確認できません。")
        with self.transaction() as db:
            row = db.execute("SELECT value FROM setting WHERE name='generation'").fetchone()
            if row:
                latest, previous = json.loads(row[0])
                if stamp <= latest:
                    if digest != previous:
                        raise Conflict("以前に確認した安定版カタログと署名世代が矛盾しています。")
                    return
            db.execute("INSERT OR REPLACE INTO setting VALUES ('generation',?)", (json.dumps([stamp, digest]),))

    def setting(self, name, value=None):
        with self.transaction() as db:
            if value is not None:
                db.execute("INSERT OR REPLACE INTO setting VALUES (?,?)", (name, json.dumps(value)))
            row = db.execute("SELECT value FROM setting WHERE name=?", (name,)).fetchone()
            return json.loads(row[0]) if row else None
