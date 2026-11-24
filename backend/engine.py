"""Project observations onto the main window and bind each action to its reviewed plan."""
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from firmware_api import fw
from hardware import target_installed, target_version_matches
from journal import Conflict


@dataclass(frozen=True)
class Actor:
    sender: str
    uid: int
    session: str
    bus: str
    writable: bool
    desktop: str
    process: str


DISPLAY = ("target", "source", "checked", "changes", "scope", "checksum", "token", "signed", "synced")
VERIFIED = ("token", "guid", "device", "current", "target", "version_format", "checksum", "cab_sha512",
            "appstream_id", "remote_id", "scope",
            "payload_sha256", "payload_size", "settings_fingerprint", "shutdown", "daemon_owner", "target_raw")
TITLES = {"idle": "この PC の更新を確認", "available": "この機種に適用できる更新があります",
          "current": "適用可能な新版はありません", "review": "更新内容を確認してください",
          "issuing": "更新準備を受付済み", "uncertain": "更新依頼の受付を確認中",
          "pending": "再起動待ち", "complete": "目標版の導入を確認", "hold": "確認が必要です"}
RESULTS = {
    "installed": ("complete", "実機の BIOS 版と起動予約の解消を確認しました。"),
    "unapplied": ("hold", "起動予約は解消しましたが、実機の BIOS は目標版に達していません。現在版から再照会できます。"),
    "failed": ("hold", "以前の更新の試行失敗を記録しました。現在版から再照会できます。"),
    "unattributed": ("hold", "以前の更新の結果を確定できませんでした。現在版から再照会できます。"),
}


def same_target(plan, obs):
    return bool(obs["can_identify"] and plan.get("guid") == obs["guid"] and plan.get("device") == obs["device"])


def free(obs):
    return obs["reservation"] == "clear" and obs["running"] is False


def settled_after_boot(plan, obs):
    return bool(obs["boot"] and plan["boot"] and plan["boot"] != obs["boot"] and obs["machine"]
                and plan["machine"] == obs["machine"] and same_target(plan, obs)
                and plan.get("version_format") == obs["version_format"] and free(obs))


class Engine:
    def __init__(self, db, platform):
        self.db = db
        self.platform = platform
        self.lock = threading.RLock()
        self.candidates = {}
        self.drafts = {}
        self.catalog_lock = threading.Lock()

    def observation(self, plan=None):
        obs = self._read_observation(plan)
        if plan or obs["reservation"] != "foreign" or not obs["machine"]:
            return obs
        last = self.db.last(obs["machine"], obs["boot"])
        if (not last or last["outcome"] != "installed" or last["machine"] != obs["machine"]
                or last.get("binding", {}).get("delivery") != "capsule-on-disk"
                or not same_target(last, obs) or not target_version_matches(last, obs)):
            return obs
        # A finished operation can identify its exact residual capsule for status and catalog checks.
        # The second read must see no active delivery route, including a request for the old capsule.
        checked = self._read_observation(last)
        if (settled_after_boot(last, checked) and target_installed(last, checked)
                and checked["attempt_comparable"] and not checked["new_failure"]):
            return checked
        return obs

    def _read_observation(self, plan):
        obs = self.platform.observe(plan)
        obs["machine"] = self.db.machine_key(obs["machine"])
        return obs

    def required(self, actor):
        if not actor.writable or self.platform.actor(actor.sender) != actor:
            raise Conflict("アクティブなローカル画面で「更新計画を開く」を選んでください。")

    def drop_draft(self, sender):
        old = self.drafts.pop(sender, None)
        if old:
            old[2].close()

    def disconnect(self, sender):
        with self.lock:
            self.drop_draft(sender)
            self.candidates.pop(sender, None)

    def verified(self, result):
        if "signed_timestamp" in result:
            self.db.catalog_generation(result["signed_timestamp"], result["catalog_sha256"])
            timestamp = result.get("download_signed_timestamp", result["signed_timestamp"])
            result["signed"] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        return result

    def read_catalog(self, actor, mode, guid, cabinet=None):
        # Serialize authenticated metadata imports and reads of the distribution's shared index.
        with self.catalog_lock:
            result = self.verified(self.platform.worker(mode, guid, cabinet))
            if mode == "check" and result.get("refresh_required"):
                self.required(actor)
                self.platform.refresh(guid, self.db, lambda: self.required(actor))
                result = self.verified(self.platform.worker(mode, guid))
            return result

    def reconcile(self, plan, obs):
        same_boot = bool(obs["boot"] and obs["boot"] == plan["boot"])
        bound = (obs["machine"] == plan["machine"] and (same_boot or bool(obs["machine"])))
        if not bound or not same_target(plan, obs) or plan.get("version_format") != obs["version_format"]:
            return "hold", "承認した PC または BIOS と今回の観測を照合できません。"
        if obs["new_failure"] and not self.db.setting("failure-" + plan["id"]):
            self.db.setting("failure-" + plan["id"], {"current": obs["current"], "status": obs["attempt_status"]})
        if self.db.setting("failure-" + plan["id"]):
            return "hold", "対象版への新しい試行失敗があります。作業者による確認が必要です。"
        if obs["reservation"] == "matching":
            return "pending", "予約した更新は次の指定された起動時に適用され得ます。"
        if obs["reservation"] in ("unknown", "foreign"):
            return "hold", "予約と承認内容を照合中です。新しい更新の準備を保留します。"
        if not same_boot and obs["boot"] and free(obs):
            if not obs["attempt_comparable"]:
                return "hold", "起動予約は解消しましたが、実機の試行結果を確定できません。必要なら計画を作り直せます。"
            outcome = "installed" if target_installed(plan, obs) else "unapplied"
            self.db.finish(plan["id"], outcome, obs["current"], observed_boot=obs["boot"])
            self.candidates.clear()
            return RESULTS[outcome]
        if plan["receipt"] == "accepted":
            return "issuing", "fwupd が依頼を受け付けました。起動予約と実機の版を照合しています。"
        return "uncertain", "受付または配置結果が未確定です。実機の状態を再確認してください。"

    def status(self, actor):
        # The journal can change while reading hardware. Never render a permission from an obsolete read.
        with self.lock:
            plan = self.db.active()
            obs = self.observation(plan)
            v = dict(model=obs["model"], current=obs["current"],
                     state="idle", detail=obs["detail"], can_check=actor.writable and obs["can_identify"],
                     can_prepare=False, can_approve=False, can_power=False, plan="", power="")
            v.update({k: obs[k] for k in ("support_url", "recovery_url") if obs.get(k)})
            if plan:
                state, reason = self.reconcile(plan, obs)
                active = self.db.active() is not None
                v.update({k: plan[k] for k in DISPLAY if k in plan})
                v.update(state=state, plan=plan["id"], detail="\n".join(filter(None, (reason, obs["detail"]))),
                         can_check=bool(actor.writable and not active and obs["can_identify"]),
                         result_this_boot=not active,
                         power=obs["power"] or ("shutdown" if plan.get("shutdown") else "reboot"))
                v["can_power"] = bool(actor.writable and actor.desktop and state == "pending" and obs["power"] and
                                      not plan.get("power_id") and plan["uid"] == actor.uid)
                if state == "pending" and plan.get("power_id"):
                    v["detail"] += "\nデスクトップへの終了要求の結果を確認中です。"
                elif state == "pending" and actor.writable and not actor.desktop:
                    v["detail"] += "\nこのデスクトップの終了操作を照合できません。予約は保持されています。"
                v["can_replan"] = bool(state == "hold" and active and actor.writable
                                       and plan["uid"] == actor.uid and settled_after_boot(plan, obs))
            elif not obs["can_identify"] or not free(obs):
                v.update(state="hold", can_check=False,
                         detail=obs["detail"] or "実機の更新対象または既存予約を確認できません。")
            else:
                self.idle_view(v, actor, obs)
            if not actor.writable:
                hint = "閲覧専用です。承認にはランチャーの「更新計画を開く」を使います。"
                if getattr(self.platform, "portable", False):
                    hint = ("閲覧専用です。この画面をログイン中のデスクトップに直接対応付けられません。"
                            "そのデスクトップの端末から同じ AppImage を開き直してください。")
                v["detail"] = (v["detail"] + "\n" + hint).strip()
            history = self.db.history(obs["machine"], obs["boot"])
            v["history"] = "\n".join(filter(None, (history, obs["history"])))
            v["title"] = "電源オフ待ち" if v["state"] == "pending" and v["power"] == "shutdown" else TITLES[v["state"]]
            return v

    def idle_view(self, v, actor, obs):
        item = self.candidates.get(actor.sender)
        draft = self.drafts.get(actor.sender)
        if draft and (draft[0] != actor or not same_target(draft[1], obs) or draft[1]["current"] != obs["current"]):
            self.drop_draft(actor.sender)
            draft = None
        saved = self.db.approval()
        if draft or saved:
            p = saved or draft[1]
            can_resume = (actor.writable and p["uid"] == actor.uid and same_target(p, obs) and
                          p["current"] == obs["current"] and p["machine"] == obs["machine"] and
                          p["boot"] == obs["boot"])
            v.update({k: p[k] for k in DISPLAY if k in p})
            v.update(state="review", plan=p["id"], device=p["device"], daemon_owner=p["daemon_owner"],
                     can_approve=can_resume, can_check=False, cab_sha512=p.get("cab_sha512", ""),
                     remote_id=p.get("remote_id", ""), appstream_id=p.get("appstream_id", ""),
                     recovery_detail=p.get("recovery_detail", ""),
                     recovery_required=p.get("recovery_required", True),
                     power="shutdown" if p["shutdown"] else "reboot", detail="対象・配布ファイル・起動先を照合しました。")
            if saved:
                v["detail"] = "前回の承認は記録済みです。送信前の計画を再確認してください。"
                v["can_replan"] = bool(actor.writable and p["uid"] == actor.uid and free(obs))
            if p.get("higher_release_detail"):
                v["detail"] += "\n" + p["higher_release_detail"]
            return
        if item and same_target(item, obs) and item["current"] == obs["current"]:
            v.update({k: item[k] for k in DISPLAY if k in item})
            v.update(state=item["state"], detail=item.get("detail", ""),
                     can_prepare=bool(actor.writable and item["state"] == "available"))
            if item["state"] == "hold":
                cache = self.db.setting("display-cache")
                if cache and same_target(cache, obs) and cache["current"] == obs["current"]:
                    v.update({k: cache[k] for k in ("target", "source", "checked") if k in cache})
                    v["cached"] = True
            return
        last = self.db.last(obs["machine"], obs["boot"])
        if last and obs["machine"] and last["machine"] == obs["machine"] and same_target(last, obs):
            this_boot = bool(obs["boot"] and last["observed_boot"] == obs["boot"])
            outcome = last["outcome"]
            if outcome == "installed":
                show_result = target_installed(last, obs)
            else:
                show_result = this_boot and outcome in RESULTS and last["observed"] == obs["current"]
            if show_result:
                state, detail = RESULTS[outcome]
                v.update({k: last[k] for k in DISPLAY if k in last})
                v.update(state=state, result_this_boot=this_boot,
                         detail="\n".join(filter(None, (detail, obs["detail"]))))
                return
        cache = self.db.setting("display-cache")
        if cache and same_target(cache, obs) and cache["current"] == obs["current"]:
            v.update({k: cache[k] for k in ("target", "source", "checked") if k in cache})
            v["cached"] = True
            v["detail"] = "前回確認した配布情報です。現在の候補は再照会して確認します。"
        elif not v["detail"]:
            v["detail"] = "この PC の BIOS に適用できる安定版を確認します。"

    def check(self, actor):
        self.required(actor)
        obs = self.observation()
        if self.db.active() or not obs["can_identify"] or not free(obs):
            return self.status(actor)
        with self.lock:
            if actor.sender in self.drafts:
                return self.status(actor)
            self.candidates.pop(actor.sender, None)
        item = self.read_catalog(actor, "check", obs["guid"])
        self.required(actor)
        # A diagnostic still belongs to the observed machine when the remote could not be reached.
        for k in ("guid", "device", "current"):
            item.setdefault(k, obs[k])
        with self.lock:
            self.candidates[actor.sender] = item
            if item["state"] in ("available", "current"):
                self.db.setting("display-cache", {k: item[k] for k in
                                ("guid", "device", "current", "target", "source", "checked") if k in item})
        return self.status(actor)

    def prepare(self, actor, token):
        self.required(actor)
        with self.lock:
            v = self.status(actor)
            if not token or not v["can_prepare"] or v.get("token") != token:
                raise Conflict("候補が変わりました。現在の配布情報と予約を確認してください。")
            candidate = self.candidates[actor.sender]
        cab = self.platform.cabinet()
        try:
            p = self.read_catalog(actor, "prepare", candidate["guid"], cab)
            self.platform.metadata_clear(self.db)
            if p.get("state") != "available" or p.get("token") != token:
                raise Conflict(p.get("detail") or "照会した候補と配布物が一致しません。")
            p["binding"] = self.platform.preflight(p)
            p["recovery_required"] = self.platform.recovery_required(p)
            obs = self.observation()
            self.required(actor)
            self.platform.confirm_owner(p["daemon_owner"])
            if not same_target(p, obs) or p["current"] != obs["current"] or not obs["boot"] or not free(obs):
                raise Conflict("検証中に実機の対象、現在版または予約が変わりました。")
            p.update({k: obs[k] for k in ("boot", "machine", "attempt_version", "attempt_status")})
            p.update(id=str(uuid.uuid4()), uid=actor.uid)
            with self.lock:
                if self.db.active() or self.candidates.get(actor.sender) is not candidate:
                    raise Conflict("別の操作が進んでいます。現在の状態を確認してください。")
                self.drop_draft(actor.sender)
                self.drafts[actor.sender] = (actor, p, cab)
                cab = None
            return self.status(actor)
        except (Conflict, fw.Hold, fw.Error) as exc:
            # A failed preflight changes the next action to checking the source
            # or fixing the reported condition. Keep the last target as history.
            with self.lock:
                if self.candidates.get(actor.sender) is candidate:
                    held = {k: candidate[k] for k in ("device", "guid", "current")}
                    self.candidates[actor.sender] = dict(held, state="hold", detail=str(exc)[:1024])
            raise
        finally:
            if cab is not None:
                cab.close()

    def dismiss(self, actor, plan_id):
        self.required(actor)
        with self.lock:
            draft = self.drafts.get(actor.sender)
            saved = self.db.approval()
            own_saved = saved and saved["id"] == plan_id and saved["uid"] == actor.uid
            if not own_saved and (not draft or draft[0] != actor or draft[1]["id"] != plan_id):
                raise Conflict("この接続で表示した計画を確認できません。")
            self.drop_draft(actor.sender)
            if own_saved:
                self.db.cancel_approval(plan_id)
        return self.status(actor)

    def authorize(self, actor, plan_id):
        self.required(actor)
        with self.lock:
            draft = self.drafts.get(actor.sender)
            saved = self.db.approval()
            if self.db.active() or (saved and saved["id"] != plan_id):
                raise Conflict("この画面で承認できる更新計画を確認できません。")
            if draft and draft[0] == actor and draft[1]["id"] == plan_id:
                p = draft[1]
                cabinet = os.fdopen(os.dup(draft[2].fileno()), "rb")
                mode = "revalidate"
            elif saved and saved["uid"] == actor.uid and self.status(actor)["can_approve"]:
                p = saved
                cabinet = self.platform.cabinet()
                mode = "prepare"
                draft = None
            else:
                raise Conflict("この画面で承認できる更新計画を確認できません。")
        try:
            self.db.approve(p)
            updated = self.read_catalog(actor, mode, p["guid"], cabinet)
            self.platform.metadata_clear(self.db)
            if updated.get("state") != "available" or any(updated.get(k) != p.get(k) for k in VERIFIED):
                raise Conflict("承認後に配布物・適用条件が変わりました。配布情報を再確認してください。")
            with self.catalog_lock, self.lock:
                self.platform.metadata_clear(self.db)
                if draft is not None and self.drafts.get(actor.sender) is not draft:
                    raise Conflict("計画が変更されました。")
                # The catalog lock may have been held by another network request.
                # Read hardware and power after that wait, before issuing permission.
                if self.platform.recovery_required(dict(p)) and not p.get("recovery_required"):
                    raise Conflict("暗号化の回復手段を確認してから再承認してください。")
                if self.platform.preflight(p) != p["binding"]:
                    raise Conflict("承認後に起動先が変わりました。")
                obs = self.observation()
                if (not free(obs) or not same_target(p, obs) or
                        any(obs.get(k) != p.get(k) for k in
                            ("boot", "machine", "current", "attempt_version", "attempt_status"))):
                    raise Conflict("承認後に機器の状態が変わりました。")
                self.verified(updated)
                self.platform.confirm_owner(p["daemon_owner"])
                self.required(actor)
                cabinet.seek(0)
                with self.platform.claim(p):
                    self.db.issue(p, actor.sender, p["daemon_owner"], actor.bus, from_approval=True)
                self.drop_draft(actor.sender)
            return plan_id, p["daemon_owner"], p["device"], cabinet
        except BaseException:
            cabinet.close()
            with self.lock:
                self.db.cancel_approval(plan_id)
                if self.drafts.get(actor.sender) is draft:
                    self.drop_draft(actor.sender)
                    self.candidates.pop(actor.sender, None)
            raise

    def report(self, actor, operation, accepted):
        self.db.report(operation, actor.sender, actor.bus, accepted)
        return self.status(actor)

    def decline_authorization(self, sender, operation):
        with self.lock:
            self.db.decline_authorization(operation, sender, self.platform.bus_id, self.platform.release_claim)

    def replan(self, actor, plan_id):
        self.required(actor)
        with self.lock:
            view = self.status(actor)
            if view.get("plan") != plan_id or not view.get("can_replan"):
                raise Conflict("以前の依頼・予約の解消を確認できません。")
            p = self.db.active()
            if p:
                obs = self.observation(p)
                if not settled_after_boot(p, obs):
                    raise Conflict("以前の依頼、予約または機器との一致を確認できません。")
                failed = bool(self.db.setting("failure-" + p["id"]))
                self.db.finish(p["id"], "failed" if failed else "unattributed", obs["current"], observed_boot=obs["boot"])
                self.candidates.clear()
            else:
                self.db.cancel_approval(plan_id)
            self.disconnect(actor.sender)
        return self.check(actor)

    def power_check(self, actor, p):
        self.required(actor)
        if not p or p["uid"] != actor.uid:
            raise Conflict("この利用者の予約を確認できません。")
        obs = self.observation(p)
        action = self.platform.check_power_action(p, obs)
        self.platform.power_allowed(actor, action)
        return action

    def power(self, actor, plan_id):
        with self.lock:
            p = self.db.active()
            if not p or p["id"] != plan_id:
                raise Conflict("予約を確認できません。")
            action = self.power_check(actor, p)
            return self.db.power(plan_id, actor.sender, actor.bus), actor.desktop, action

    def recheck_power(self, actor, request):
        p = self.db.active()
        if not p or (p["power_id"], p["power_sender"], p["power_bus"]) != (request, actor.sender, actor.bus):
            raise Conflict("照合中の起動操作が変わりました。")
        self.power_check(actor, p)
