import copy
import sys
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from hardware import check_power_action
from firmware_api import fw
from journal import Conflict, Journal, METADATA_PENDING
from engine import Actor, Engine


class Machine:
    bus_id = "bus"

    def __init__(self):
        self.observation = dict(model="NB-14", current="1.20", device="a" * 40, guid="g", boot="boot-1",
                                machine="uuid", can_identify=True, reservation="clear", running=False, detail="",
                                history="", new_failure=False, attempt_comparable=True, power="", version_format="pair",
                                attempt_version=20, attempt_status=0)
        self.candidate = dict(state="available", guid="g", current="1.20", device="a" * 40, target="1.24",
                              source="LVFS", checked="2026-11-21", token="candidate", daemon_owner=":1.6",
                              version_format="pair", shutdown=False, scope="BIOS", checksum="a" * 64,
                              settings_fingerprint="settings", payload_sha256="b" * 64, payload_size=64,
                              signed_timestamp=10, catalog_sha256="c" * 64)

    def observe(self, plan):
        return dict(self.observation)

    def worker(self, mode, guid, cabinet=None):
        return copy.deepcopy(self.candidate)

    def preflight(self, plan):
        return {"esp": "disk-a"}

    def cabinet(self):
        return tempfile.TemporaryFile()

    def recovery_required(self, plan):
        return False

    def metadata_clear(self, db):
        return None

    def claim(self, plan):
        return nullcontext()

    def confirm_owner(self, owner):
        if owner != ":1.6":
            raise Conflict("daemon changed")

    def actor(self, sender):
        return Actor(sender, 1000, "s1", self.bus_id, sender != ":2.0", "gnome", "pid:42")


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Journal(Path(self.tmp.name) / "state")
        self.machine = Machine()
        self.engine = Engine(self.db, self.machine)
        self.addCleanup(self.engine.disconnect, ":1.2")
        self.user = self.machine.actor(":1.2")

    def review(self):
        candidate = self.engine.check(self.user)
        self.assertTrue(candidate["can_prepare"])
        return self.engine.prepare(self.user, candidate["token"])

    def test_manual_power_check_is_read_only_and_needs_current_power(self):
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        self.machine.observation.update(reservation="matching", power="reboot")
        self.machine.check_power_action = check_power_action
        self.machine.power_allowed = lambda *_: None
        self.assertEqual(self.engine.check_power(self.user, operation), "reboot")
        self.assertIsNone(self.db.active()["power_id"])
        self.machine.observation["power"] = ""
        with self.assertRaises(fw.Hold):
            self.engine.check_power(self.user, operation)
        self.assertIsNone(self.db.active()["power_id"])

    def test_review_keeps_model_and_installed_version_and_dismiss_never_issues(self):
        review = self.review()
        self.assertEqual((review["model"], review["current"], review["target"]), ("NB-14", "1.20", "1.24"))
        self.assertTrue(review["can_approve"])
        self.assertIsNone(self.db.active())
        self.engine.dismiss(self.user, review["plan"])
        self.assertIsNone(self.db.active())
        with self.assertRaises(Conflict):
            self.engine.authorize(self.user, review["plan"])

    def test_prepare_returns_its_own_draft_even_when_another_approval_takes_precedence(self):
        other = self.machine.actor(":1.3")
        self.addCleanup(self.engine.disconnect, other.sender)
        other_plan = self.engine.prepare(other, self.engine.check(other)["token"])["plan"]
        token = self.engine.check(self.user)["token"]
        worker = self.machine.worker

        def save_other_approval_during_download(mode, guid, cabinet=None):
            if mode == "prepare":
                self.db.approve(self.engine.drafts[other.sender][1])
            return worker(mode, guid, cabinet)

        self.machine.worker = save_other_approval_during_download
        reply = self.engine.prepare(self.user, token)
        self.assertEqual(reply["plan"], other_plan)
        self.assertNotEqual(reply.get("prepared_draft"), other_plan)
        self.assertTrue(reply.get("prepared_draft"))
        self.engine.dismiss(self.user, reply["prepared_draft"])
        self.assertEqual(self.db.approval()["id"], other_plan)

    def test_uncertain_metadata_import_allows_lookup_but_blocks_cab_download(self):
        def check_import(db):
            if db.setting("metadata-request"):
                raise Conflict(METADATA_PENDING)

        self.machine.metadata_clear = check_import
        requested = []
        original_worker = self.machine.worker

        def worker(mode, *args):
            requested.append(mode)
            return original_worker(mode, *args)

        self.machine.worker = worker
        view = self.engine.check(self.user)
        self.assertTrue(view["can_prepare"])
        self.db.setting("metadata-request", {"id": "previous-import"})
        blocked = self.engine.check(self.user)
        self.assertFalse(blocked["can_prepare"])
        self.assertTrue(blocked["can_check"])
        self.assertEqual(blocked["target"], view["target"])
        self.assertIn(METADATA_PENDING, blocked["detail"])
        with self.assertRaises(Conflict):
            self.engine.prepare(self.user, view["token"])
        self.assertEqual(requested, ["check", "check"])
        self.db.setting("metadata-request", {})
        self.assertTrue(self.engine.prepare(self.user, view["token"])["can_approve"])

    def test_issued_operation_survives_gui_disconnect_and_is_not_resent(self):
        review = self.review()
        operation, owner, device, file = self.engine.authorize(self.user, review["plan"])
        file.close()
        self.engine.disconnect(self.user.sender)
        self.assertEqual(self.engine.status(self.user)["state"], "uncertain")
        with self.assertRaises(Conflict):
            self.engine.authorize(self.user, review["plan"])
        self.engine.report(self.user, operation, True)
        self.machine.observation.update(reservation="matching", power="reboot")
        view = self.engine.status(self.user)
        self.assertEqual((view["state"], view["current"]), ("pending", "1.20"))
        self.machine.observation.update(boot="boot-2", reservation="clear", current="1.24", power="")
        complete = self.engine.status(self.user)
        self.assertEqual(complete["state"], "complete")
        self.assertIn("目標版を確認", complete["history"])
        self.assertIn("1.24", self.db.history(self.db.machine_key("uuid")))

    def test_definite_firmware_rejection_allows_reapproval_only_after_reservation_clears(self):
        released = []
        self.machine.release_claim = lambda plan: released.append(plan["id"])
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        with self.assertRaises(Conflict):
            self.engine.report_rejection(self.machine.actor(":1.3"), operation)
        self.machine.observation.update(reservation="foreign")
        view = self.engine.report_rejection(self.user, operation)
        self.assertFalse(view["can_check"])
        self.assertEqual(self.db.active()["receipt"], "rejected")
        self.assertEqual(released, [])

        self.machine.observation["reservation"] = "clear"
        self.assertTrue(self.engine.status(self.user)["can_check"])
        self.assertEqual(released, [operation])
        last = self.db.last(self.db.machine_key("uuid"), "boot-1")
        self.assertEqual((last["id"], last["outcome"]), (operation, "rejected"))
        reopened = Engine(Journal(self.db.path), self.machine)
        review = reopened.prepare(self.user, reopened.check(self.user)["token"])
        new, _, _, cabinet = reopened.authorize(self.user, review["plan"])
        cabinet.close()
        self.assertNotEqual(new, operation)

    def test_unknown_or_accepted_install_cannot_be_treated_as_definite_rejection_without_a_receipt(self):
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        view = self.engine.report(self.user, operation, False)
        self.assertEqual(view["state"], "uncertain")
        self.assertFalse(view["can_check"])
        self.engine.report(self.user, operation, True)
        with self.assertRaises(Conflict):
            self.engine.report_rejection(self.user, operation)
        self.assertEqual(self.db.active()["receipt"], "accepted")

    def test_pending_power_from_previous_boot_does_not_block_new_request_for_same_reservation(self):
        self.machine.check_power_action = check_power_action
        self.machine.power_allowed = lambda actor, action: None
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        self.machine.observation.update(reservation="matching", power="reboot")
        original, _, action = self.engine.power(self.user, operation)
        self.assertEqual(action, "reboot")
        self.engine.recheck_power(self.user, original)
        self.db.power_reply(original, self.user.sender, self.user.bus, False)
        self.assertFalse(self.engine.status(self.user)["can_power"])
        with self.assertRaises(Conflict):
            self.engine.power(self.user, operation)

        self.machine.observation["boot"] = "boot-2"
        reopened = Engine(Journal(self.db.path), self.machine)
        current = self.machine.actor(":1.3")
        view = reopened.status(current)
        self.assertEqual(view["state"], "pending")
        self.assertTrue(view["can_power"])
        with self.assertRaises(Conflict):
            reopened.recheck_power(self.user, original)
        later, _, action = reopened.power(current, operation)
        self.assertNotEqual(later, original)
        self.assertEqual(action, "reboot")
        with self.assertRaises(Conflict):
            self.db.power_reply(original, self.user.sender, self.user.bus, True)
        reopened.recheck_power(current, later)

    def test_recorded_failure_blocks_all_power_entrypoints_after_esrt_changes(self):
        self.machine.check_power_action = check_power_action
        self.machine.power_allowed = lambda *_: None
        plan = self.review()["plan"]
        *_, cabinet = self.engine.authorize(self.user, plan)
        cabinet.close()
        self.machine.observation.update(reservation="matching", power="reboot")
        request, _, _ = self.engine.power(self.user, plan)
        self.machine.observation.update(new_failure=True, attempt_status=1)
        self.assertEqual(self.engine.status(self.user)["state"], "hold")
        self.machine.observation.update(new_failure=False, attempt_status=0)
        self.assertEqual(self.engine.status(self.user)["state"], "hold")
        with self.assertRaises(Conflict):
            self.engine.recheck_power(self.user, request)
        self.db.power_reply(request, self.user.sender, self.user.bus, True)
        for verify in (self.engine.power, self.engine.check_power):
            with self.subTest(method=verify.__name__), self.assertRaises(Conflict):
                verify(self.user, plan)
        self.assertIsNone(self.db.active(plan_id=plan)["power_id"])

    def test_external_reservation_wins_over_cached_catalog(self):
        self.engine.check(self.user)
        self.machine.observation["reservation"] = "foreign"
        view = self.engine.status(self.user)
        self.assertFalse(view["can_prepare"])
        self.assertEqual(view["current"], "1.20")
        with self.assertRaises(Conflict):
            self.engine.prepare(self.user, "candidate")

    def test_inactive_residue_keeps_release_information_but_withholds_preparation(self):
        self.machine.observation["prepare_block"] = "処理済みファイルが残っています。"
        view = self.engine.check(self.user)
        self.assertEqual((view["state"], view["target"]), ("hold", "1.24"))
        self.assertIn("処理済みファイル", view["detail"])
        self.assertTrue(view["can_check"])
        self.assertFalse(view["can_prepare"])
        with self.assertRaises(Conflict):
            self.engine.prepare(self.user, view["token"])

        self.machine.observation.pop("prepare_block")
        self.assertTrue(self.engine.status(self.user)["can_prepare"])

    def test_equivalent_versions_after_boot_record_installation(self):
        self.machine.candidate["target"] = "1.024"
        view = self.review()
        *_, cabinet = self.engine.authorize(self.user, view["plan"])
        cabinet.close()
        self.machine.observation.update(boot="boot-2", current="1.24")
        self.assertEqual(self.engine.status(self.user)["state"], "complete")
        self.assertEqual(self.db.last(self.db.machine_key("uuid"), "boot-2")["outcome"], "installed")

    def test_boot_result_is_visible_to_every_reader_for_that_boot(self):
        for installed in (True, False):
            with self.subTest(installed=installed):
                old_boot = "installed-issue" if installed else "unapplied-issue"
                result_boot = old_boot + "-result"
                self.machine.observation.update(boot=old_boot, current="1.20")
                self.machine.candidate.update(current="1.20", target="1.24")
                review = self.review()
                *_, cabinet = self.engine.authorize(self.user, review["plan"])
                cabinet.close()
                current = "1.24" if installed else "1.20"
                state = "complete" if installed else "hold"
                self.machine.observation.update(boot=result_boot, current=current)
                first = self.engine.status(self.user)
                self.assertEqual(first["state"], state)
                result = self.engine.status(self.machine.actor(":2.0"))
                self.assertEqual(result["state"], state)
                self.assertTrue(result.get("result_this_boot"))
                self.assertTrue(first.get("result_this_boot"))
                self.assertFalse(result["can_check"])
                reopened = Engine(Journal(self.db.path), self.machine)
                result = reopened.status(self.machine.actor(":2.0"))
                self.assertEqual(result["state"], state)
                self.assertTrue(result.get("result_this_boot"))
                self.machine.candidate.update(current=current, target="1.25")
                self.assertEqual(self.engine.check(self.user)["state"], "available")
                self.machine.observation["boot"] += "-later"
                self.assertFalse(reopened.status(self.user).get("result_this_boot"))

    def test_failed_device_preflight_shows_the_reason_and_changes_the_next_action(self):
        candidate = self.engine.check(self.user)

        def no_profile(plan):
            raise Conflict("対応する機種設定を確認できません。")

        self.machine.preflight = no_profile
        with self.assertRaises(Conflict):
            self.engine.prepare(self.user, candidate["token"])
        status = self.engine.status(self.user)
        self.assertEqual((status["state"], status["model"], status["current"]), ("hold", "NB-14", "1.20"))
        self.assertIn("機種設定", status["detail"])
        self.assertTrue(status["can_check"])
        self.assertFalse(status["can_prepare"])

    def test_source_change_or_view_only_connection_cannot_authorize(self):
        review = self.review()
        with self.assertRaises(Conflict):
            self.engine.authorize(self.machine.actor(":2.0"), review["plan"])
        self.machine.candidate["token"] = "different"
        with self.assertRaises(Conflict):
            self.engine.authorize(self.user, review["plan"])
        self.assertIsNone(self.db.active())

    def test_newer_catalog_during_final_device_check_invalidates_permission(self):
        review = self.review()
        preflight = self.machine.preflight

        def another_refresh(plan):
            self.db.catalog_generation(11, "f" * 64)
            return preflight(plan)

        self.machine.preflight = another_refresh
        with self.assertRaises(Conflict):
            self.engine.authorize(self.user, review["plan"])
        self.assertIsNone(self.db.active())

    def authorize_after_catalog_wait(self, change):
        review = self.review()
        original = self.engine.catalog_lock

        class CatalogLock:
            entries = 0

            def __enter__(self):
                original.acquire()
                self.entries += 1
                if self.entries == 2:  # State at the end of a competing catalog request.
                    change()

            def __exit__(self, *exc):
                original.release()

        self.engine.catalog_lock = CatalogLock()
        with self.assertRaises(Conflict):
            *_, cabinet = self.engine.authorize(self.user, review["plan"])
            cabinet.close()
        self.assertIsNone(self.db.active())

    def test_authorize_rechecks_reservation_after_catalog_wait(self):
        self.authorize_after_catalog_wait(lambda: self.machine.observation.update(reservation="foreign"))

    def test_authorize_rechecks_power_after_catalog_wait(self):
        def power_lost():
            def preflight(plan):
                raise Conflict("AC disconnected")
            self.machine.preflight = preflight

        self.authorize_after_catalog_wait(power_lost)

    def test_additional_encryption_requires_a_fresh_explicit_approval(self):
        kinds = ["LUKS"]

        def recovery(plan):
            plan["recovery_detail"] = "・".join(kinds)
            return True

        self.machine.recovery_required = recovery
        original = self.review()
        self.assertEqual(original["recovery_detail"], "LUKS")
        kinds.append("BitLocker")
        with self.assertRaisesRegex(Conflict, "回復手段"):
            *_, cabinet = self.engine.authorize(self.user, original["plan"])
            cabinet.close()
        self.assertIsNone(self.db.active())
        self.assertIsNone(self.db.approval())
        revised = self.review()
        self.assertIn("BitLocker", revised["recovery_detail"])
        self.assertNotEqual(original["plan"], revised["plan"])
        *_, cabinet = self.engine.authorize(self.user, revised["plan"])
        cabinet.close()

    def test_can_replan_after_reboot_without_esrt_attempt_result(self):
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        self.engine.report(self.user, operation, True)
        self.machine.observation.update(boot="boot-2", attempt_status=None, attempt_comparable=False)
        for _ in range(2):
            view = self.engine.status(self.user)
            self.assertEqual(view["state"], "hold")
            self.assertIn("確定できません", view["detail"])
            self.assertTrue(view["can_replan"])
            self.assertFalse(view["can_power"])

        self.assertFalse(self.engine.status(self.machine.actor(":2.0"))["can_replan"])
        self.machine.observation["machine"] = "different"
        self.assertFalse(self.engine.status(self.user).get("can_replan", False))
        with self.assertRaises(Conflict):
            self.engine.replan(self.user, operation)
        self.machine.observation["machine"] = "uuid"
        self.assertEqual(self.engine.replan(self.user, operation)["state"], "available")
        self.assertEqual(self.db.last(self.db.machine_key("uuid"), "boot-2")["outcome"], "unattributed")

    def test_moved_disk_retains_old_pc_record_and_allows_an_independent_plan(self):
        first = self.review()["plan"]
        _, _, _, cabinet = self.engine.authorize(self.user, first)
        cabinet.close()
        self.engine.report(self.user, first, True)

        self.machine.observation.update(machine="another-pc", boot="boot-2", reservation="foreign")
        blocked = self.engine.check(self.user)
        self.assertFalse(blocked["can_check"])
        self.assertFalse(blocked["can_prepare"])
        self.machine.observation["reservation"] = "clear"
        second = self.review()["plan"]
        self.assertNotEqual(first, second)
        self.assertNotIn("受付済み", self.engine.status(self.user)["history"])
        _, _, _, cabinet = self.engine.authorize(self.user, second)
        cabinet.close()

        self.machine.observation.update(machine="uuid", boot="boot-3", reservation="matching", power="reboot")
        reopened = Engine(Journal(self.db.path), self.machine)
        restored = reopened.status(self.user)
        self.assertEqual((restored["plan"], restored["state"]), (first, "pending"))
        self.assertEqual(self.db.active(plan_id=second)["receipt"], "unknown")

        self.machine.observation.update(machine="", boot="boot-4", reservation="clear")
        ambiguous = reopened.status(self.user)
        self.assertFalse(ambiguous["can_check"])
        self.assertFalse(ambiguous.get("can_replan", False))

    def test_unidentified_old_operation_still_blocks_a_known_pc_until_reconciled(self):
        self.machine.observation["machine"] = ""
        first = self.review()["plan"]
        _, _, _, cabinet = self.engine.authorize(self.user, first)
        cabinet.close()
        self.machine.observation.update(machine="another-pc", boot="boot-2")
        view = self.engine.status(self.user)
        self.assertEqual(view["plan"], first)
        self.assertFalse(view["can_check"])

    def test_administrator_can_resolve_sent_operation_with_unconfirmed_result(self):
        plan = self.review()["plan"]
        _, _, _, cabinet = self.engine.authorize(self.user, plan)
        cabinet.close()
        self.engine.report(self.user, plan, True)
        actor = self.machine.actor
        self.machine.actor = lambda sender: replace(actor(sender), uid=1001)
        colleague = self.machine.actor(":1.3")
        self.machine.observation.update(boot="boot-2", attempt_status=None, attempt_comparable=False)
        self.assertTrue(self.engine.status(colleague).get("can_take_over", False))
        self.assertFalse(self.engine.status(colleague).get("can_replan", False))

        def reservation_appeared(_):
            self.machine.observation["reservation"] = "foreign"

        self.machine.require_administrator = reservation_appeared
        with self.assertRaises(Conflict):
            self.engine.take_over(colleague, plan)
        self.assertIsNotNone(self.db.active(plan_id=plan))
        self.machine.observation["reservation"] = "clear"
        confirmations = []
        self.machine.require_administrator = confirmations.append
        self.assertTrue(self.engine.take_over(colleague, plan)["can_check"])
        self.assertEqual(confirmations, [colleague])
        self.assertIsNone(self.db.active(plan_id=plan))
        self.assertEqual(self.db.last(self.db.machine_key("uuid"), "boot-2")["outcome"], "unattributed")

    def test_new_boot_can_discard_an_unattributed_operation_only_after_route_clears(self):
        self.machine.observation["machine"] = ""
        review = self.review()
        operation, _, _, cabinet = self.engine.authorize(self.user, review["plan"])
        cabinet.close()
        self.engine.report(self.user, operation, True)
        self.assertFalse(self.engine.status(self.user).get("can_replan", False))
        self.machine.observation.update(boot="boot-2", reservation="matching", power="reboot")
        self.assertFalse(self.engine.status(self.user)["can_replan"])

        self.machine.observation.update(reservation="clear", current="1.24", power="", running=True)
        self.assertFalse(self.engine.status(self.user)["can_replan"])
        self.machine.observation["running"] = False
        self.machine.candidate.update(current="1.24", target="1.25")
        review = self.engine.status(self.user)
        self.assertEqual((review["state"], review["current"]), ("hold", "1.24"))
        self.assertTrue(review["can_replan"])
        self.assertFalse(review["can_power"])
        self.assertEqual(self.engine.replan(self.user, operation)["state"], "available")
        self.assertIsNone(self.db.active())
        result = self.db.last("", "boot-2")
        self.assertEqual((result["outcome"], result["receipt"]), ("unattributed", "accepted"))
        self.assertIsNone(self.db.last("", "unrelated-boot"))

        reopened = Engine(Journal(self.db.path), self.machine)
        self.assertIn("帰属は未確認", reopened.status(self.user)["history"])

    def test_saved_consent_before_permission_is_recoverable_without_automatic_send(self):
        review = self.review()
        saved = dict(self.engine.drafts[self.user.sender][1])
        self.db.approve(saved)
        self.engine.disconnect(self.user.sender)
        reopened = Engine(Journal(self.db.path), self.machine)
        view = reopened.status(self.user)
        self.assertEqual((view["state"], view["plan"]), ("review", review["plan"]))
        self.assertFalse(reopened.status(self.machine.actor(":2.0"))["can_approve"])
        self.assertIsNone(self.db.active())
        op, _, _, cabinet = reopened.authorize(self.user, view["plan"])
        cabinet.close()
        self.assertEqual(self.db.active()["id"], op)
        self.assertIsNone(self.db.approval())

    def save_approval_for_recovery(self):
        review = self.review()
        self.db.approve(self.engine.drafts[self.user.sender][1])
        self.engine.disconnect(self.user.sender)
        return review["plan"]

    def test_another_user_needs_administrator_authorization_to_release_saved_approval(self):
        op = self.save_approval_for_recovery()
        self.machine.observation["boot"] = "boot-2"
        actor = self.machine.actor
        self.machine.actor = lambda sender: replace(actor(sender), uid=1001)
        other = self.machine.actor(":1.3")
        viewer = self.machine.actor(":2.0")
        self.assertFalse(self.engine.status(viewer).get("can_take_over", False))
        self.assertTrue(self.engine.status(other).get("can_take_over", False))

        def deny(actor):
            raise Conflict("administrator declined")

        self.machine.require_administrator = deny
        with self.assertRaisesRegex(Conflict, "declined"):
            self.engine.take_over(other, op)
        self.assertEqual(self.db.approval()["id"], op)
        self.assertIsNone(self.db.active())

        authorizations = []
        self.machine.require_administrator = authorizations.append
        reopened = Engine(Journal(self.db.path), self.machine)
        self.assertTrue(reopened.take_over(other, op)["can_check"])
        self.assertEqual(authorizations, [other])
        self.assertIsNone(self.db.approval())
        self.assertIsNone(self.db.active())
        new = reopened.prepare(other, reopened.check(other)["token"])
        self.assertNotEqual(new["plan"], op)
        self.assertTrue(new["can_approve"])

    def test_numeric_uid_reused_by_a_new_login_does_not_own_the_saved_approval(self):
        op = self.save_approval_for_recovery()
        original_actor = self.machine.actor
        self.machine.actor = lambda sender: replace(original_actor(sender), session="new-logind-session")
        reused_uid = self.machine.actor(":1.3")
        for boot in ("boot-1", "boot-2"):
            with self.subTest(boot=boot):
                self.machine.observation["boot"] = boot
                view = self.engine.status(reused_uid)
                self.assertFalse(view["can_approve"])
                self.assertFalse(view["can_replan"])
                self.assertTrue(view["can_take_over"])
                with self.assertRaises(Conflict):
                    self.engine.dismiss(reused_uid, op)
                with self.assertRaises(Conflict):
                    self.engine.replan(reused_uid, op)
                with self.assertRaises(Conflict):
                    self.engine.authorize(reused_uid, op)
                self.assertEqual(self.db.approval()["id"], op)
        admins = []
        self.machine.require_administrator = admins.append
        self.engine.take_over(reused_uid, op)
        self.assertEqual(admins, [reused_uid])
        self.assertIsNone(self.db.approval())

    def test_administrator_cannot_release_an_approval_after_a_reservation_appears(self):
        op = self.save_approval_for_recovery()
        actor = self.machine.actor
        self.machine.actor = lambda sender: replace(actor(sender), uid=1001)
        other = self.machine.actor(":1.3")
        self.assertTrue(self.engine.status(other).get("can_take_over", False))
        self.machine.require_administrator = lambda actor: self.machine.observation.update(reservation="foreign")
        with self.assertRaises(Conflict):
            self.engine.take_over(other, op)
        self.assertEqual(self.db.approval()["id"], op)

    def test_failed_online_check_keeps_last_dated_candidate_as_history_only(self):
        self.engine.check(self.user)
        self.machine.candidate.update(state="hold", target="", source="", checked="", detail="ネットワークに接続できません")
        view = self.engine.check(self.user)
        self.assertTrue(view["cached"])
        self.assertEqual((view["target"], view["checked"]), ("1.24", "2026-11-21"))
        self.assertFalse(view["can_prepare"])
