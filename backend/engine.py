"""Project observations onto the main window and bind each action to its reviewed plan."""
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from firmware_api import fw
from hardware import target_installed, target_version_matches
from journal import Conflict, failure_text


@dataclass(frozen=True)
class Actor:
    sender: str
    uid: int
    session: str
    bus: str
    writable: bool
    desktop: str
    process: str
    can_open_plan: bool = False
    session_version: tuple[str, int, int] | None = None


DISPLAY = ("target", "source", "checked", "changes", "scope", "checksum", "token", "signed", "synced",
           "remote_id", "appstream_id", "cab_sha512")
CACHE_DISPLAY = ("target", "source", "checked", "signed", "synced")
VERIFIED = ("token", "guid", "device", "current", "target", "version_format", "checksum", "cab_sha512",
            "appstream_id", "remote_id", "scope",
            "payload_sha256", "payload_size", "settings_fingerprint", "shutdown", "daemon_owner", "target_raw")
TITLES = {"idle": "この PC の更新を確認", "available": "この機種に適用できる更新があります",
          "current": "適用可能な新版はありません", "review": "更新内容を確認してください",
          "issuing": "更新準備を受付済み", "uncertain": "更新依頼の受付を確認中",
          "pending": "再起動待ち", "complete": "目標版の導入を確認", "hold": "確認が必要です"}
RESULTS = {
    "installed": ("complete", "実機の BIOS 版と起動予約の解消を確認しました。"),
    "unapplied": ("hold", "起動予約は解消しました。実機の BIOS は目標版と異なります。現在版から再照会できます。"),
    "failed": ("hold", "以前の更新の試行失敗を記録しました。現在版から再照会できます。"),
    "unattributed": ("hold", "以前の更新の結果を確定できませんでした。現在版から再照会できます。"),
    "rejected": ("hold", "更新依頼の未送達または配置前の拒否と、起動予約がないことを確認しました。現在版から再照会できます。"),
}
ATTEMPT_FAILED = "対象版への新しい試行失敗があります。作業者による確認が必要です。"


def same_target(plan, obs):
    return bool(obs["can_identify"] and plan.get("guid") == obs["guid"] and plan.get("device") == obs["device"])


def free(obs):
    return obs["reservation"] == "clear" and obs["running"] is False


def display_cache_key(obs):
    if obs["machine"]:
        return "display-cache:machine:" + obs["machine"]
    return "display-cache:boot" if obs["boot"] else None


def settled_after_boot(plan, obs, *, allow_unidentified=False):
    same_machine = bool(obs["machine"]) and plan["machine"] == obs["machine"]
    if allow_unidentified and not (plan["machine"] and obs["machine"]):
        same_machine = True
    return bool(obs["boot"] and plan["boot"] and plan["boot"] != obs["boot"]
                and same_machine and same_target(plan, obs)
                and plan.get("version_format") == obs["version_format"] and free(obs))


def owns_approval(plan, actor, obs):
    return bool(actor.session and actor.bus and obs["boot"] and plan["uid"] == actor.uid
                and plan["boot"] == obs["boot"] and plan["machine"] == obs["machine"]
                and plan.get("approval_session") == actor.session and plan.get("approval_bus") == actor.bus)


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

    def current_operation(self):
        obs = self.observation()
        pending = self.db.pending_operations(obs["machine"], obs["boot"])
        if len(pending) != 1:
            return None, obs, bool(pending)
        plan = pending[0]
        bound = self.observation(plan)
        if (obs["machine"], obs["boot"]) != (bound["machine"], bound["boot"]):
            return None, bound, True
        return plan, bound, False

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
            self.platform.confirm_owner(result["daemon_owner"])
            self.db.catalog_generation(result["signed_timestamp"], result["catalog_sha256"])
            timestamp = result.get("download_signed_timestamp", result["signed_timestamp"])
            result["signed"] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        return result

    def read_catalog(self, actor, mode, guid, cabinet=None):
        # Serialize authenticated metadata imports and reads of the distribution's shared index.
        with self.catalog_lock:
            if mode != "check":
                self.platform.metadata_clear(self.db)
            result = self.verified(self.platform.worker(mode, guid, cabinet))
            if mode == "check" and result.get("refresh_required"):
                self.required(actor)
                self.platform.refresh(guid, self.db, lambda: self.required(actor))
                result = self.verified(self.platform.worker(mode, guid))
            return result

    def failed_attempt(self, plan, obs):
        return obs["new_failure"] or bool(self.db.failure(plan["id"]))

    def reconcile(self, plan, obs):
        same_boot = bool(obs["boot"] and obs["boot"] == plan["boot"])
        bound = (obs["machine"] == plan["machine"] and (same_boot or bool(obs["machine"])))
        if not bound or not same_target(plan, obs) or plan.get("version_format") != obs["version_format"]:
            return "hold", "承認した PC または BIOS と今回の観測を照合できません。"
        if plan["receipt"] == "rejected":
            if obs["boot"] and free(obs):
                self.db.finish(plan["id"], "rejected", obs["current"], observed_boot=obs["boot"],
                               release_claim=self.platform.release_claim if same_boot else None)
                self.candidates.clear()
                return RESULTS["rejected"]
            return "hold", "更新依頼の未送達または配置前の拒否を記録しました。既存の予約と進行中の処理を確認しています。"
        failure = self.db.failure(plan["id"], obs if obs["new_failure"] else None)
        if failure:
            return "hold", ATTEMPT_FAILED + "\n" + failure_text(failure)
        if obs["reservation"] == "matching":
            if not same_boot and not obs["attempt_comparable"]:
                return "hold", "予約は残っていますが、起動後の実機の試行結果を承認した更新に照合できません。"
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
            plan, obs, ambiguous = self.current_operation()
            saved = None
            reason = "未解決の操作と今回の PC を一意に照合できません。" if ambiguous else ""
            if not plan and not ambiguous:
                approvals = self.db.pending_approvals(obs["machine"], obs["boot"])
                if len(approvals) > 1:
                    reason = "保存済みの承認と今回の PC を一意に照合できません。"
                elif approvals:
                    saved = approvals[0]
                    if (obs["reservation"] == "foreign" and obs["boot"]
                            and (saved["boot"], saved["machine"]) == (obs["boot"], obs["machine"])
                            and same_target(saved, obs)
                            and self.db.recover_approval_claim(saved, self.platform.recover_claim)):
                        checked = self.observation()
                        if (obs["machine"], obs["boot"]) != (checked["machine"], checked["boot"]):
                            reason = "保存済みの承認と今回の PC を一意に照合できません。"
                        obs = checked
            v = dict(model=obs["model"], current=obs["current"],
                     state="idle", detail=obs["detail"], can_check=actor.writable and obs["can_identify"],
                     can_open_plan=actor.can_open_plan,
                     can_prepare=False, can_approve=False, can_dismiss=False, can_power=False, plan="", power="")
            v.update({k: obs[k] for k in ("support_url", "recovery_url") if obs.get(k)})
            if reason:
                v.update(state="hold", can_check=False, needs_attention=True, detail=reason)
            elif plan:
                state, reason = self.reconcile(plan, obs)
                active = self.db.active(plan_id=plan["id"]) is not None
                v.update({k: plan[k] for k in DISPLAY if k in plan})
                v.update(state=state, plan=plan["id"], detail="\n".join(filter(None, (reason, obs["detail"]))),
                         can_check=bool(actor.writable and not active and obs["can_identify"]),
                         result_this_boot=not active,
                         power=obs["power"] or ("shutdown" if plan.get("shutdown") else "reboot"))
                if state == "pending" and plan["power_id"] and not plan["power_boot"] and obs["boot"]:
                    self.db.bind_legacy_power_boot(plan["id"], plan["power_id"], obs["boot"])
                power_pending = bool(plan["power_id"] and
                                     (not obs["boot"] or plan["power_boot"] in (None, obs["boot"])))
                v["can_power"] = bool(actor.writable and actor.desktop and state == "pending" and obs["power"] and
                                      not power_pending and plan["uid"] == actor.uid)
                if state == "pending" and power_pending:
                    v["detail"] += "\nデスクトップへの終了要求の結果を確認中です。"
                elif state == "pending" and actor.writable and not actor.desktop:
                    v["detail"] += "\nこのデスクトップの終了操作を照合できません。予約は保持されています。"
                # A UID alone cannot identify the same account after another boot.
                v["can_replan"] = False
                v["can_take_over"] = (state == "hold" and active and actor.writable
                                      and settled_after_boot(plan, obs, allow_unidentified=True))
                if v["can_take_over"]:
                    v["detail"] += "\n管理者は前回の記録を整理して、現在版から再計画できます。"
            elif not obs["can_identify"] or not free(obs):
                v.update(state="hold", can_check=False,
                         detail=obs["detail"] or "実機の更新対象または既存予約を確認できません。")
            else:
                self.idle_view(v, actor, obs, saved)
            if (v.get("source") or "").startswith("安定版ミラー ") and not v.get("synced"):
                v["synced"] = "未確認"
            if not actor.writable:
                hint = "閲覧専用です。承認にはランチャーの「更新計画を開く」を使います。"
                if actor.can_open_plan:
                    hint = "閲覧専用です。更新を準備するには通常モードの「更新計画を開く」で管理者認証を行ってください。"
                elif getattr(self.platform, "portable", False):
                    hint = ("閲覧専用です。この画面をログイン中のデスクトップに直接対応付けられません。"
                            "そのデスクトップの端末から同じ AppImage を開き直してください。")
                v["detail"] = (v["detail"] + "\n" + hint).strip()
            history = self.db.history(obs["machine"], obs["boot"])
            v["history"] = "\n".join(filter(None, (history, obs["history"])))
            v["title"] = "電源オフ待ち" if v["state"] == "pending" and v["power"] == "shutdown" else TITLES[v["state"]]
            return v

    def idle_view(self, v, actor, obs, saved):
        item = self.candidates.get(actor.sender)
        draft = self.drafts.get(actor.sender)
        prepare_block = obs.get("prepare_block")
        if draft and (prepare_block or draft[0] != actor or not same_target(draft[1], obs)
                      or any(draft[1][key] != obs[key] for key in ("current", "machine", "boot"))):
            self.drop_draft(actor.sender)
            draft = None
        try:
            self.platform.metadata_clear(self.db)
            import_block = ""
        except Conflict as exc:
            import_block = str(exc)
        prepare_block = prepare_block or import_block
        if draft or saved:
            p = saved or draft[1]
            own = owns_approval(p, actor, obs)
            can_resume = not prepare_block and actor.writable and own and same_target(p, obs) and p["current"] == obs["current"]
            v.update({k: p[k] for k in DISPLAY if k in p})
            v.update(state="review", plan=p["id"], device=p["device"], daemon_owner=p["daemon_owner"],
                     can_approve=can_resume, can_dismiss=actor.writable and own, can_check=False,
                     recovery_detail=p.get("recovery_detail", ""),
                     recovery_required=p.get("recovery_required", True),
                     power="shutdown" if p["shutdown"] else "reboot", detail="対象・配布ファイル・起動先を照合しました。")
            if saved:
                v["detail"] = "前回の承認は記録済みです。送信前の計画を再確認してください。"
                v["can_replan"] = actor.writable and own and free(obs)
                v["can_take_over"] = actor.writable and not own and free(obs)
                if v["can_take_over"]:
                    v["detail"] = "元の承認者をこのログインで確認できません。管理者は未送信の承認を解除できます。"
            if p.get("higher_release_detail"):
                v["detail"] += "\n" + p["higher_release_detail"]
            if prepare_block:
                v["detail"] += "\n" + prepare_block
            return
        if (item and same_target(item, obs)
                and all(item[k] == obs[k] for k in ("current", "machine", "boot"))):
            v.update({k: item[k] for k in DISPLAY if k in item})
            v.update(state=item["state"], detail=item.get("detail", ""),
                     can_prepare=bool(actor.writable and item["state"] == "available"))
            if prepare_block and item["state"] == "available":
                v.update(state="hold", can_prepare=False, detail=prepare_block)
            if item["state"] == "hold":
                self.load_display_cache(v, obs)
            return
        last = self.db.last(obs["machine"], obs["boot"])
        if last and same_target(last, obs):
            this_boot = bool(obs["boot"] and last["observed_boot"] == obs["boot"])
            outcome = last["outcome"]
            same_machine = bool(obs["machine"]) and last["machine"] == obs["machine"]
            if outcome == "installed":
                show_result = same_machine and target_installed(last, obs)
            else:
                show_result = (this_boot and (same_machine or outcome in ("unattributed", "rejected"))
                               and outcome in RESULTS and last["observed"] == obs["current"])
            if show_result:
                state, detail = RESULTS[outcome]
                failure = failure_text(self.db.failure(last["id"])) if outcome == "failed" else ""
                v.update({k: last[k] for k in DISPLAY if k in last})
                v.update(state=state, result_this_boot=this_boot,
                         detail="\n".join(filter(None, (detail, failure, obs["detail"]))))
                return
        if self.load_display_cache(v, obs):
            v["detail"] = "前回確認した配布情報です。現在の候補は再照会して確認します。"
        elif not v["detail"]:
            v["detail"] = "この PC の BIOS に適用できる安定版を確認します。"
        if import_block:
            v.update(state="hold", detail=import_block)

    def load_display_cache(self, view, obs):
        key = display_cache_key(obs)
        cache = self.db.setting(key) if key else None
        if (not cache or not same_target(cache, obs) or cache.get("current") != obs["current"]
                or (not obs["machine"] and cache.get("boot") != obs["boot"])):
            return False
        view.update({k: cache[k] for k in CACHE_DISPLAY if k in cache})
        view["cached"] = True
        return True

    def check(self, actor):
        self.required(actor)
        obs = self.observation()
        if not obs["can_identify"] or not free(obs) or self.db.pending_operations(obs["machine"], obs["boot"]):
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
        item.update(machine=obs["machine"], boot=obs["boot"])
        with self.lock:
            self.candidates[actor.sender] = item
            key = display_cache_key(obs)
            if key and item["state"] in ("available", "current"):
                self.db.setting(key, {k: item[k] for k in ("guid", "device", "current", "boot", *CACHE_DISPLAY)
                                      if k in item})
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
            if (not same_target(p, obs) or p["current"] != obs["current"] or not obs["boot"] or not free(obs)
                    or any(candidate[k] != obs[k] for k in ("machine", "boot"))):
                raise Conflict("検証中に実機の対象、現在版または予約が変わりました。")
            p.update({k: obs[k] for k in ("boot", "machine", "attempt_version", "attempt_status")})
            p.update(id=str(uuid.uuid4()), uid=actor.uid, approval_session=actor.session, approval_bus=actor.bus)
            with self.lock:
                if (self.db.pending_operations(obs["machine"], obs["boot"])
                        or self.candidates.get(actor.sender) is not candidate):
                    raise Conflict("別の操作が進んでいます。現在の状態を確認してください。")
                self.drop_draft(actor.sender)
                self.drafts[actor.sender] = (actor, p, cab)
                cab = None
            # The global view can show a different window's saved approval.
            return dict(self.status(actor), prepared_draft=p["id"])
        except (Conflict, fw.Hold, fw.Error) as exc:
            # A failed preflight changes the next action to checking the source
            # or fixing the reported condition. Keep the last target as history.
            with self.lock:
                if self.candidates.get(actor.sender) is candidate:
                    held = {k: candidate[k] for k in ("device", "guid", "current", "machine", "boot")}
                    self.candidates[actor.sender] = dict(held, state="hold", detail=str(exc)[:1024])
            raise
        finally:
            if cab is not None:
                cab.close()

    def dismiss(self, actor, plan_id):
        self.required(actor)
        with self.lock:
            draft = self.drafts.get(actor.sender)
            saved = self.db.approval(plan_id=plan_id)
            owns_draft = draft and draft[0] == actor and draft[1]["id"] == plan_id
            owns_plan = owns_approval(saved, actor, self.observation()) if saved else owns_draft
            if not owns_plan:
                raise Conflict("この接続で表示した計画を確認できません。")
            if owns_draft:
                self.drop_draft(actor.sender)
            if saved:
                self.db.cancel_approval(plan_id)
        return self.status(actor)

    def authorize(self, actor, plan_id, *, prepare_reply=None):
        self.required(actor)
        with self.lock:
            draft = self.drafts.get(actor.sender)
            if draft and draft[0] == actor and draft[1]["id"] == plan_id:
                p = draft[1]
                cabinet = os.fdopen(os.dup(draft[2].fileno()), "rb")
                mode = "revalidate"
            else:
                p = self.db.approval(plan_id=plan_id)
                view = self.status(actor)
                if not p or view["plan"] != plan_id or not view["can_approve"]:
                    raise Conflict("この画面で承認できる更新計画を確認できません。")
                cabinet = self.platform.cabinet()
                mode = "prepare"
                draft = None
            try:
                self.db.approve(p)
            except BaseException:
                cabinet.close()
                raise
        try:
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
                if self.platform.preflight(p) != p["binding"]:
                    raise Conflict("承認後に起動先が変わりました。")
                obs = self.observation()
                if (not free(obs) or not same_target(p, obs) or
                        any(obs.get(k) != p.get(k) for k in
                            ("boot", "machine", "current", "attempt_version", "attempt_status"))):
                    raise Conflict("承認後に機器の状態が変わりました。")
                recovery = dict(p)
                recovery_required = self.platform.recovery_required(recovery)
                if (recovery_required != p["recovery_required"]
                        or recovery.get("recovery_detail", "") != p.get("recovery_detail", "")):
                    raise Conflict("暗号化の照合結果が変わりました。回復手段を確認してから再承認してください。")
                self.verified(updated)
                self.platform.confirm_owner(p["daemon_owner"])
                cabinet.seek(0)
                result = (plan_id, p["daemon_owner"], p["device"], cabinet)
                if prepare_reply is not None:
                    # Reserve the response FD before journaling a permission that may be sent.
                    with cabinet:
                        result = prepare_reply(*result)
                self.required(actor)
                with self.platform.claim(p):
                    self.db.issue(p, actor.sender, p["daemon_owner"], actor.bus, from_approval=True)
                self.drop_draft(actor.sender)
            return result
        except BaseException:
            cabinet.close()
            with self.lock:
                self.db.cancel_approval(plan_id)
                if self.drafts.get(actor.sender) is draft:
                    self.drop_draft(actor.sender)
                    self.candidates.pop(actor.sender, None)
            raise

    def record_receipt(self, sender, bus, operation, accepted=None):
        with self.lock:
            if accepted is None:
                self.db.report_rejection(operation, sender, bus)
            else:
                self.db.report(operation, sender, bus, accepted)

    def report(self, actor, operation, accepted):
        self.record_receipt(actor.sender, actor.bus, operation, accepted)
        return self.status(actor)

    def report_rejection(self, actor, operation):
        self.record_receipt(actor.sender, actor.bus, operation)
        return self.status(actor)

    def decline_authorization(self, sender, operation):
        with self.lock:
            self.db.decline_authorization(operation, sender, self.platform.bus_id, self.platform.release_claim)

    def take_over(self, actor, plan_id):
        self.required(actor)
        view = self.status(actor)
        if view["plan"] != plan_id or not view.get("can_take_over"):
            raise Conflict("管理者が整理できる計画を確認できません。")
        self.platform.require_administrator(actor)
        with self.lock:
            self.required(actor)
            view = self.status(actor)
            if view["plan"] != plan_id or not view.get("can_take_over"):
                raise Conflict("管理者認証中に計画または予約が変わりました。")
            p = self.db.active(plan_id=plan_id)
            if p:
                self.finish_for_replan(p)
            else:
                self.db.cancel_approval(plan_id)
            for sender, (_, draft, _) in list(self.drafts.items()):
                if draft["id"] == plan_id:
                    self.drop_draft(sender)
            self.candidates.clear()
            return self.status(actor)

    def finish_for_replan(self, p):
        obs = self.observation(p)
        if not settled_after_boot(p, obs, allow_unidentified=True):
            raise Conflict("以前の依頼、予約または機器との一致を確認できません。")
        if obs["machine"] and p["machine"] == obs["machine"]:
            self.reconcile(p, obs)
            if self.db.active(plan_id=p["id"]) is None:
                return
            failed = self.db.failure(p["id"])
        else:
            failed = False
        self.db.finish(p["id"], "failed" if failed else "unattributed", obs["current"], observed_boot=obs["boot"])
        self.candidates.clear()

    def replan(self, actor, plan_id):
        self.required(actor)
        with self.lock:
            view = self.status(actor)
            if view.get("plan") != plan_id or not view.get("can_replan"):
                raise Conflict("以前の依頼・予約の解消を確認できません。")
            self.db.cancel_approval(plan_id)
            self.disconnect(actor.sender)
        return self.check(actor)

    def power_check(self, actor, p):
        self.required(actor)
        if not p or p["uid"] != actor.uid:
            raise Conflict("この利用者の予約を確認できません。")
        obs = self.observation(p)
        if self.failed_attempt(p, obs):
            raise Conflict(ATTEMPT_FAILED)
        if p["receipt"] == "rejected":
            raise Conflict("配置前の拒否を記録した計画のため、起動操作を確認できません。")
        action = self.platform.check_power_action(p, obs)
        self.platform.power_allowed(actor, action)
        self.required(actor)
        return action, obs["boot"]

    def check_power(self, actor, plan_id):
        """Check the reservation for the user's manual shutdown or restart."""
        with self.lock:
            p = self.db.active(plan_id=plan_id)
            if not p:
                raise Conflict("予約を確認できません。")
            action, _ = self.power_check(actor, p)
            return action

    def power(self, actor, plan_id):
        with self.lock:
            p = self.db.active(plan_id=plan_id)
            if not p:
                raise Conflict("予約を確認できません。")
            action, boot = self.power_check(actor, p)
            return self.db.power(plan_id, actor.sender, actor.bus, boot), actor.desktop, action

    def recheck_power(self, actor, request):
        with self.lock:
            p = self.db.active(power_id=request)
            if not p or (p["power_id"], p["power_sender"], p["power_bus"]) != (request, actor.sender, actor.bus):
                raise Conflict("照合中の起動操作が変わりました。")
            _, boot = self.power_check(actor, p)
            if p["power_boot"] is None:
                self.db.bind_legacy_power_boot(p["id"], request, boot)
            elif p["power_boot"] != boot:
                raise Conflict("電源要求は以前の起動で記録されたものです。")
