"""Protocol and local audit ledger for the VeritasPack demo."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from functools import wraps

GENESIS = "0" * 64
CHALLENGE_TTL = 60


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tag_message(uid: str, counter: int, challenge: str, tamper: bool) -> bytes:
    return canonical({"uid": uid, "counter": counter, "challenge": challenge, "tamper": tamper}).encode()


def tag_mac(key: bytes, uid: str, counter: int, challenge: str, tamper: bool) -> str:
    return hmac.new(key, tag_message(uid, counter, challenge, tamper), hashlib.sha256).hexdigest()


class ProtocolError(Exception):
    def __init__(self, code: str, detail: str):
        self.code, self.detail = code, detail
        super().__init__(detail)


def synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapped


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, sku TEXT NOT NULL,
            batch TEXT NOT NULL, uid TEXT UNIQUE NOT NULL, tag_key TEXT NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0, tampered INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER
        );
        CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id),
            expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT NOT NULL,
            kind TEXT NOT NULL, detail TEXT NOT NULL, timestamp INTEGER NOT NULL,
            prev_hash TEXT NOT NULL, hash TEXT NOT NULL
        );
        """)

    def close(self):
        self.db.close()

    @synchronized
    def seed(self):
        if self.db.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
            return
        samples = [
            ("VP-1001", "Aster Precision Watch", "AST-W42", "BATCH-24A", "04:A1:9C:21:10:01"),
            ("VP-1002", "Helix Medical Kit", "HLX-MK7", "BATCH-24B", "04:A1:9C:21:10:02"),
            ("VP-1003", "Orion Camera Lens", "ORN-L85", "BATCH-24C", "04:A1:9C:21:10:03"),
        ]
        with self.db:
            for pid, name, sku, batch, uid in samples:
                self.db.execute("INSERT INTO products(id,name,sku,batch,uid,tag_key) VALUES(?,?,?,?,?,?)",
                                (pid, name, sku, batch, uid, secrets.token_hex(32)))
                self._append(pid, "PROVISIONED", "Secure tag provisioned; key retained in local demo vault")

    @synchronized
    def reset(self):
        with self.db:
            self.db.execute("DELETE FROM challenges")
            self.db.execute("DELETE FROM events")
            self.db.execute("DELETE FROM products")
            self.db.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        self.seed()

    def _append(self, pid: str, kind: str, detail: str):
        last = self.db.execute("SELECT hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        prev = last[0] if last else GENESIS
        timestamp = int(time.time())
        cur = self.db.execute("INSERT INTO events(product_id,kind,detail,timestamp,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                              (pid, kind, detail, timestamp, prev, ""))
        sequence = cur.lastrowid
        digest = hashlib.sha256(canonical({"sequence": sequence, "product_id": pid, "kind": kind,
                             "detail": detail, "timestamp": timestamp, "prev_hash": prev}).encode()).hexdigest()
        self.db.execute("UPDATE events SET hash=? WHERE sequence=?", (digest, sequence))
        return digest

    @synchronized
    def ledger_valid(self) -> bool:
        previous = GENESIS
        for row in self.db.execute("SELECT * FROM events ORDER BY sequence"):
            expected = hashlib.sha256(canonical({key: row[key] for key in
                ("sequence", "product_id", "kind", "detail", "timestamp", "prev_hash")}).encode()).hexdigest()
            if row["prev_hash"] != previous or not hmac.compare_digest(row["hash"], expected):
                return False
            previous = row["hash"]
        return True

    @synchronized
    def products(self):
        rows = self.db.execute("SELECT id,name,sku,batch,uid,counter,tampered,last_seen FROM products ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    @synchronized
    def product(self, pid: str):
        row = self.db.execute("SELECT id,name,sku,batch,uid,counter,tampered,last_seen FROM products WHERE id=?", (pid,)).fetchone()
        if not row:
            raise ProtocolError("NOT_FOUND", "Unknown product")
        return dict(row)

    @synchronized
    def events(self, pid: str | None = None, limit: int = 30):
        if pid:
            rows = self.db.execute("SELECT * FROM events WHERE product_id=? ORDER BY sequence DESC LIMIT ?", (pid, limit))
        else:
            rows = self.db.execute("SELECT * FROM events ORDER BY sequence DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    @synchronized
    def challenge(self, pid: str) -> str:
        self.product(pid)
        nonce = secrets.token_hex(16)
        self.db.execute("INSERT INTO challenges(nonce,product_id,expires_at) VALUES(?,?,?)",
                        (nonce, pid, int(time.time()) + CHALLENGE_TTL))
        return nonce

    @synchronized
    def verify_scan(self, product_id: str, uid: str, counter: int, challenge: str, tamper: bool, mac: str):
        pid = product_id
        if not isinstance(counter, int) or isinstance(counter, bool) or counter < 1 or counter > 2**64 - 1:
            raise ProtocolError("BAD_COUNTER", "Counter must be a positive 64-bit integer")
        row = self.db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not row:
            raise ProtocolError("NOT_FOUND", "Unknown product")
        # Claim the nonce atomically and commit it even if later proof checks fail.
        claim = self.db.execute("UPDATE challenges SET used=1 WHERE nonce=? AND product_id=? AND used=0 AND expires_at>=?",
                                (challenge, pid, int(time.time())))
        if claim.rowcount != 1:
            raise ProtocolError("CHALLENGE_INVALID", "Challenge missing, expired, or already used")
        with self.db:
            if uid != row["uid"]:
                raise ProtocolError("TAG_MISMATCH", "Tag UID does not belong to this product")
            expected = tag_mac(bytes.fromhex(row["tag_key"]), uid, counter, challenge, tamper)
            if not hmac.compare_digest(mac, expected):
                raise ProtocolError("AUTH_FAILED", "Cryptographic tag proof is invalid")
            if counter <= row["counter"]:
                raise ProtocolError("REPLAY_DETECTED", "Tag counter has already been seen")
            tripped = bool(row["tampered"]) or tamper
            self.db.execute("UPDATE products SET counter=?,tampered=?,last_seen=? WHERE id=?",
                            (counter, int(tripped), int(time.time()), pid))
            self._append(pid, "TAMPER_DETECTED" if tamper else "AUTHENTICATED",
                         f"Verified secure-tag proof; counter {counter}; seal {'TRIPPED' if tripped else 'INTACT'}")
        return {"authentic": True, "tampered": tripped, "counter": counter}

    @synchronized
    def virtual_proof(self, pid: str, challenge: str, *, tamper: bool = False, counter: int | None = None):
        """Local interview simulator only. Production readers generate proof on the secure tag."""
        row = self.db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if not row:
            raise ProtocolError("NOT_FOUND", "Unknown product")
        value = counter if counter is not None else row["counter"] + 1
        return {"product_id": pid, "uid": row["uid"], "counter": value, "challenge": challenge,
                "tamper": tamper, "mac": tag_mac(bytes.fromhex(row["tag_key"]), row["uid"], value, challenge, tamper)}
