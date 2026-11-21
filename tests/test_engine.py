import copy
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from journal import Conflict, Journal
from engine import Actor, Engine


class Machine:
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
        return Actor(sender, 1000, "s1", "bus", sender != ":2.0", "gnome", "pid:42")


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

    def test_review_keeps_model_and_installed_version_and_dismiss_never_issues(self):
        review = self.review()
        self.assertEqual((review["model"], review["current"], review["target"]), ("NB-14", "1.20", "1.24"))
        self.assertTrue(review["can_approve"])
        self.assertIsNone(self.db.active())
        self.engine.dismiss(self.user, review["plan"])
        self.assertIsNone(self.db.active())
        with self.assertRaises(Conflict):
            self.engine.authorize(self.user, review["plan"])

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

    def test_external_reservation_wins_over_cached_catalog(self):
        self.engine.check(self.user)
        self.machine.observation["reservation"] = "foreign"
        view = self.engine.status(self.user)
        self.assertFalse(view["can_prepare"])
        self.assertEqual(view["current"], "1.20")
        with self.assertRaises(Conflict):
            self.engine.prepare(self.user, "candidate")

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

    def test_failed_online_check_keeps_last_dated_candidate_as_history_only(self):
        self.engine.check(self.user)
        self.machine.candidate.update(state="hold", target="", source="", checked="", detail="ネットワークに接続できません")
        view = self.engine.check(self.user)
        self.assertTrue(view["cached"])
        self.assertEqual((view["target"], view["checked"]), ("1.24", "2026-11-21"))
        self.assertFalse(view["can_prepare"])
