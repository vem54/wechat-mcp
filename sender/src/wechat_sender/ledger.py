"""Durable at-most-once submission claims; uncertain outcomes are never retried."""
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from .backend_protocol import SenderError, native_local_result_fields

TERMINAL = frozenset({"submitted", "observed_in_local_history", "delivery_confirmed", "rejected", "outcome_unknown"})


def fingerprint(recipient_id: str, text: str) -> str:
    value = json.dumps(["wechat-sender-v1", recipient_id, text], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now(UTC).isoformat()


class Ledger:
    """Durable claims with optional exact outgoing text in the private MCP outbox.

    A committed dispatching claim is permanent even if the process crashes before
    calling the backend. This deliberately prefers a missing send over a duplicate.
    """

    def __init__(self, path: Path):
        self.path = Path(path).absolute()
        if any(p.is_symlink() for p in (self.path, *self.path.parents)):
            raise SenderError("unsafe_ledger_path")
        try:
            self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            parent = self.path.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise SenderError("unsafe_ledger_permissions")
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise SenderError("unsafe_ledger_permissions")
            finally:
                os.close(fd)
            with self.connection() as db:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1, 2):
                    raise SenderError("unsupported_ledger_schema")
                if version == 0:
                    if db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                        raise SenderError("unsupported_ledger_schema")
                    db.execute("CREATE TABLE operations(request_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,"
                               "operation_id TEXT UNIQUE NOT NULL,account_id TEXT NOT NULL,recipient_id TEXT NOT NULL,"
                               "state TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,result TEXT,"
                               "outgoing_text TEXT)")
                    db.execute("PRAGMA user_version=2")
                elif version == 1:
                    # Existing digests, states and identifiers stay intact. Old
                    # text cannot be reconstructed and is explicitly left NULL.
                    db.execute("ALTER TABLE operations ADD COLUMN outgoing_text TEXT")
                    db.execute("PRAGMA user_version=2")
        except (OSError, sqlite3.Error):
            raise SenderError("ledger_unavailable") from None

    @contextmanager
    def connection(self, *, read_only=False):
        if any(p.is_symlink() for p in (self.path, *self.path.parents)):
            raise SenderError("unsafe_ledger_path")
        db = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if read_only else "?mode=rw"),
                             uri=True, timeout=2, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            if read_only:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
            else:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise SenderError("ledger_unavailable") from None
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _existing(row, digest):
        if row["payload_sha256"] != digest:
            raise SenderError("request_id_reused_with_different_payload")
        result = (json.loads(row["result"]) if row["result"] else
                  {"status": "outcome_unknown", "diagnostic_code": "submission_may_be_in_progress"})
        return result | {"operation_id": row["operation_id"], "replayed": True}

    def lookup(self, request_id: str, digest: str) -> dict | None:
        with self.connection(read_only=True) as db:
            row = db.execute("SELECT * FROM operations WHERE request_id=?", (request_id,)).fetchone()
            return self._existing(row, digest) if row else None

    def record(self, request_id: str, *, account_id: str) -> dict | None:
        """Internal, account-bound record lookup; never allocates another intent."""
        with self.connection(read_only=True) as db:
            row = db.execute("SELECT rowid AS sequence,* FROM operations WHERE request_id=? AND account_id=?",
                             (request_id, account_id)).fetchone()
            if row is None:
                return None
            value = dict(row)
            value["result"] = json.loads(row["result"]) if row["result"] else {
                "status": "outcome_unknown", "diagnostic_code": "submission_may_be_in_progress"}
            return value

    @staticmethod
    def _evidence_rank(result):
        status = result.get("status")
        if status == "delivery_confirmed":
            return 5
        if status == "observed_in_local_history":
            return 4
        if status == "submitted":
            return 3 if native_local_result_fields(result) or result.get("diagnostic_code") == "server_acknowledged" else 1
        return 2 if status == "rejected" else 0

    def reconcile(self, operation_id: str, result: dict) -> dict:
        """Persist the first result or stronger evidence without reopening a claim.

        Rejection and proven acceptance cannot replace each other. Identity
        conflicts never overwrite existing evidence; lower-ranked observations
        (including unknown native cache entries) cannot erase stronger results.
        """
        if result.get("status") not in TERMINAL:
            raise SenderError("invalid_submission_result")
        with self.connection() as db:
            row = db.execute("SELECT * FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise SenderError("operation_not_found")
            existing = json.loads(row["result"]) if row["result"] else {"status": "outcome_unknown"}
            old_rank, new_rank = self._evidence_rank(existing), self._evidence_rank(result)
            if (existing.get("status") == "rejected" and new_rank >= 3
                    or result.get("status") == "rejected" and old_rank >= 3
                    or any(key in existing and key in result and existing[key] != result[key]
                           for key in ("local_id", "server_id", "message_id"))):
                raise SenderError("submission_evidence_conflict")
            if row["result"] is None or new_rank > old_rank:
                db.execute("UPDATE operations SET state=?,updated_at=?,result=? WHERE operation_id=?",
                           (result["status"], now(), json.dumps(result, separators=(",", ":")), operation_id))
                return result
            return existing

    def claim(self, request_id: str, digest: str, account_id: str, recipient_id: str,
              *, outgoing_text: str | None = None) -> tuple[str | None, dict | None]:
        if outgoing_text is not None and (not isinstance(outgoing_text, str)
                                           or fingerprint(recipient_id, outgoing_text) != digest):
            raise SenderError("outbox_payload_mismatch")
        with self.connection() as db:
            row = db.execute("SELECT * FROM operations WHERE request_id=?", (request_id,)).fetchone()
            if row:
                return None, self._existing(row, digest)
            operation_id = str(uuid.uuid4())
            timestamp = now()
            db.execute("INSERT INTO operations(request_id,payload_sha256,operation_id,account_id,recipient_id,"
                       "state,created_at,updated_at,result,outgoing_text) VALUES(?,?,?,?,?,'dispatching',?,?,NULL,?)",
                       (request_id, digest, operation_id, account_id, recipient_id, timestamp, timestamp, outgoing_text))
            return operation_id, None

    def list_outbox(self, account_id: str, *, limit: int = 50, before_sequence: int | None = None,
                    request_id: str | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise SenderError("invalid_limit")
        if before_sequence is not None and (type(before_sequence) is not int or not 1 <= before_sequence < 2**63):
            raise SenderError("invalid_outbox_cursor")
        clauses, parameters = ["account_id=?"], [account_id]
        if before_sequence is not None:
            clauses.append("rowid<?")
            parameters.append(before_sequence)
        if request_id is not None:
            clauses.append("request_id=?")
            parameters.append(request_id)
        parameters.append(limit + 1)
        with self.connection(read_only=True) as db:
            rows = db.execute("SELECT rowid AS sequence,* FROM operations WHERE " + " AND ".join(clauses)
                              + " ORDER BY rowid DESC LIMIT ?", parameters).fetchall()
        items = []
        for row in rows[:limit]:
            stored = json.loads(row["result"]) if row["result"] else {
                "status": "outcome_unknown", "diagnostic_code": "submission_may_be_in_progress"}
            # Fixed evidence fields only; an outbox claim never implies receipt.
            result = {key: stored[key] for key in ("status", "diagnostic_code", "message_id", "server_id") if key in stored}
            result.update(native_local_result_fields(stored))
            items.append({"sequence": row["sequence"], "request_id": row["request_id"],
                          "operation_id": row["operation_id"], "recipient_id": row["recipient_id"],
                          "text": row["outgoing_text"], "text_available": row["outgoing_text"] is not None,
                          "created_at": row["created_at"], "updated_at": row["updated_at"],
                          "submission_state": row["state"], "result": result,
                          "phone_receipt_evidence": "not_recorded", "mac_history_reconciled": False})
        return {"source": "sender_outbox", "items": items,
                "next_before_sequence": items[-1]["sequence"] if len(rows) > limit else None}

    def finish(self, operation_id: str, result: dict) -> None:
        if result.get("status") not in TERMINAL:
            raise SenderError("invalid_submission_result")
        with self.connection() as db:
            changed = db.execute("UPDATE operations SET state=?,updated_at=?,result=? "
                                 "WHERE operation_id=? AND state='dispatching'",
                                 (result["status"], now(), json.dumps(result, separators=(",", ":")), operation_id)).rowcount
            if changed != 1:
                raise SenderError("invalid_submission_transition")
