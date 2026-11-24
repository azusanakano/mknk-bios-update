import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from journal import Conflict, Journal


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state.db"
        self.db = Journal(self.path)
        self.plan = {"id": "plan-a", "boot": "boot-a", "machine": "pc", "current": "1.20",
                     "target": "1.24", "device": "a" * 40, "guid": "system", "uid": 1000}

    def test_permission_survives_restart_and_blocks_another_client(self):
        self.db.issue(self.plan, ":1.10", ":1.4", "bus")
        reopened = Journal(self.path)
        self.assertEqual(reopened.active()["receipt"], "unknown")
        with self.assertRaises(Conflict):
            reopened.issue(dict(self.plan, id="plan-b"), ":1.11", ":1.4", "bus")
        with self.assertRaises(Conflict):
            reopened.report("plan-a", ":1.11", "bus", True)
        reopened.report("plan-a", ":1.10", "bus", True)
        self.assertEqual(self.db.active()["receipt"], "accepted")
        self.db.finish("plan-a", "installed", "1.24")
        self.assertIsNone(reopened.active())
        self.assertIn("1.24", reopened.history("pc"))
        with self.assertRaises(Conflict):
            reopened.issue(dict(self.plan, id="plan-b"), ":1.11", ":1.4", "bus")

    def test_abandoned_or_uncertain_power_request_is_not_issued_twice(self):
        self.db.issue(self.plan, ":1.10", ":1.4", "bus")
        request = self.db.power("plan-a", ":1.10", "bus")
        self.db.power_reply(request, ":1.10", "bus", False)
        with self.assertRaises(Conflict):
            Journal(self.path).power("plan-a", ":1.11", "bus")
        self.db.power_reply(request, ":1.10", "bus", True)
        self.assertNotEqual(self.db.power("plan-a", ":1.10", "bus"), request)

    def test_adds_observed_boot_to_an_existing_journal_without_losing_records(self):
        self.db.issue(self.plan, ":1.10", ":1.4", "bus")
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("ALTER TABLE operation DROP COLUMN observed_boot")
            conn.commit()

        reopened = Journal(self.path)
        self.assertEqual(reopened.active()["id"], "plan-a")
        self.assertIsNone(reopened.active()["observed_boot"])
        reopened.finish("plan-a", "unapplied", "1.20", observed_boot="result-boot")
        result = Journal(self.path).last("pc", "result-boot")
        self.assertEqual((result["outcome"], result["observed_boot"]), ("unapplied", "result-boot"))

    def test_catalog_generation_persists_across_mirrors(self):
        self.db.catalog_generation(20, "a" * 64)
        self.db.catalog_generation(18, "a" * 64)
        with self.assertRaises(Conflict):
            Journal(self.path).catalog_generation(19, "b" * 64)
        self.db.catalog_generation(21, "b" * 64)

    def test_identity_is_private_stable_and_blank_stays_unknown(self):
        raw = "private-host-uuid"
        self.assertEqual(self.db.machine_key(""), "")
        token = self.db.machine_key(raw)
        self.assertNotEqual(token, raw)
        self.assertEqual(token, Journal(self.path).machine_key(raw))
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertNotIn(raw, "\n".join(conn.iterdump()))


if __name__ == "__main__":
    unittest.main()
