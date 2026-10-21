import tempfile
import unittest
from pathlib import Path

from app.core import ProtocolError, Store


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        test_root = Path(__file__).resolve().parent.parent / "data"
        test_root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_root)
        self.store = Store(Path(self.temp.name) / "demo.db")
        self.store.seed()
        self.pid = "VP-1001"

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def proof(self, **kwargs):
        nonce = self.store.challenge(self.pid)
        return self.store.virtual_proof(self.pid, nonce, **kwargs)

    def assert_code(self, code, fn):
        with self.assertRaises(ProtocolError) as ctx:
            fn()
        self.assertEqual(ctx.exception.code, code)

    def test_authentication_and_ledger(self):
        result = self.store.verify_scan(**self.proof())
        self.assertTrue(result["authentic"])
        self.assertEqual(result["counter"], 1)
        self.assertTrue(self.store.ledger_valid())

    def test_reused_challenge_and_counter_rejected(self):
        first = self.proof()
        self.store.verify_scan(**first)
        self.assert_code("CHALLENGE_INVALID", lambda: self.store.verify_scan(**first))
        self.assert_code("REPLAY_DETECTED", lambda: self.store.verify_scan(**self.proof(counter=1)))

    def test_copied_uid_without_key_rejected_and_nonce_consumed(self):
        fake = self.proof()
        real_mac = fake["mac"]
        fake["mac"] = "00" * 32
        self.assert_code("AUTH_FAILED", lambda: self.store.verify_scan(**fake))
        fake["mac"] = real_mac
        self.assert_code("CHALLENGE_INVALID", lambda: self.store.verify_scan(**fake))

    def test_tamper_latches(self):
        self.store.verify_scan(**self.proof(tamper=True))
        self.store.verify_scan(**self.proof(tamper=False))
        self.assertEqual(self.store.product(self.pid)["tampered"], 1)

    def test_ledger_detects_modified_event(self):
        self.store.db.execute("UPDATE events SET detail='forged' WHERE sequence=1")
        self.assertFalse(self.store.ledger_valid())

    def test_expired_challenge_rejected(self):
        proof = self.proof()
        self.store.db.execute("UPDATE challenges SET expires_at=0 WHERE nonce=?", (proof["challenge"],))
        self.assert_code("CHALLENGE_INVALID", lambda: self.store.verify_scan(**proof))


if __name__ == "__main__":
    unittest.main()
