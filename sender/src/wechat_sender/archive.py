"""Read-only recipient resolution against a complete reader archive generation."""
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from .backend_protocol import SenderError

CONVERSATION_PATTERN = r"conversation_[0-9a-f]{64}"
CONTACT_PATTERN = r"contact_[0-9a-f]{64}"
RECIPIENT_PATTERN = r"(?:conversation|contact)_[0-9a-f]{64}"
MAX_RECORD_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Recipient:
    recipient_id: str
    account_id: str
    generation: int
    kind: str
    display_name: str | None = field(repr=False)
    username: str = field(repr=False)

    def public(self) -> dict:
        return {"recipient_id": self.recipient_id, "display_name": self.display_name,
                "kind": self.kind, "generation": self.generation}


class ArchiveReader:
    """Never creates, migrates, refreshes or writes the installed reader archive."""

    def __init__(self, path: Path):
        self.path = Path(path).absolute()

    @contextmanager
    def connection(self):
        # Detect symlinks, unsafe ownership and permissions before SQLite opens it.
        if any(p.is_symlink() for p in (self.path, *self.path.parents)):
            raise SenderError("unsafe_archive_path")
        try:
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise SenderError("unsafe_archive_permissions")
            db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=2, isolation_level=None)
        except (OSError, sqlite3.Error):
            raise SenderError("archive_unavailable") from None
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                raise SenderError("unsupported_archive_schema")
            deadline = time.monotonic() + 2
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            yield db
        except sqlite3.Error:
            raise SenderError("archive_query_failed") from None
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
            db.close()

    @staticmethod
    def _active(db):
        row = db.execute("SELECT g.account_id,g.generation FROM archive_state s JOIN generations g "
                         "ON g.generation=s.active_generation AND g.state='complete' WHERE s.singleton=1").fetchone()
        if row is None or not isinstance(row["account_id"], str) or not row["account_id"]:
            raise SenderError("archive_not_ready")
        return row

    @staticmethod
    def _recipient(row, active, *, contact=False):
        try:
            if len(row["data"].encode("utf-8")) > MAX_RECORD_BYTES:
                raise SenderError("archive_record_too_large")
            record = json.loads(row["data"])
            recipient_id = record["contact_id" if contact else "conversation_id"]
            username = record["source_username"]
            kind = ("group" if isinstance(username, str) and username.endswith("@chatroom") else "direct") if contact else record["kind"]
            display_name = record.get("display_name")
            if (recipient_id != row["record_id"] or not re.fullmatch(CONTACT_PATTERN if contact else CONVERSATION_PATTERN, recipient_id)
                    or not isinstance(username, str) or not username or len(username) > 512
                    or any(ord(c) < 32 for c in username) or kind not in ("direct", "group")
                    or (kind == "group") != username.endswith("@chatroom")
                    or display_name is not None and not isinstance(display_name, str)):
                raise ValueError
            return Recipient(recipient_id, active["account_id"], active["generation"], kind, display_name, username)
        except (KeyError, TypeError, ValueError, UnicodeError):
            raise SenderError("invalid_recipient_record") from None

    def account_id(self) -> str:
        with self.connection() as db:
            return self._active(db)["account_id"]

    def resolve(self, recipient_id: str) -> Recipient:
        if not isinstance(recipient_id, str) or not re.fullmatch(RECIPIENT_PATTERN, recipient_id):
            raise SenderError("invalid_recipient_id")
        with self.connection() as db:
            active = self._active(db)
            return self._resolve_id(db, active, recipient_id)

    @classmethod
    def _resolve_id(cls, db, active, recipient_id: str) -> Recipient:
        """Resolve a stored ID within an existing snapshot; never derive IDs."""
        if not isinstance(recipient_id, str) or not re.fullmatch(RECIPIENT_PATTERN, recipient_id):
            raise SenderError("invalid_recipient_id")
        contact = recipient_id.startswith("contact_")
        table = "contacts" if contact else "conversations"
        row = db.execute("SELECT record_id,data FROM " + table + " WHERE generation=? AND record_id=?",
                         (active["generation"], recipient_id)).fetchone()
        if row is None:
            raise SenderError("recipient_not_found")
        selected = cls._recipient(row, active, contact=contact)
        # A contact and its conversation are expected aliases. Multiple IDs in
        # either table for the same raw username remain ambiguous.
        cls._resolve_username(db, active, selected.username)
        return selected

    @classmethod
    def _resolve_username(cls, db, active, username: str) -> Recipient:
        if (not isinstance(username, str) or not username or len(username) > 512
                or any(ord(char) < 32 for char in username)):
            raise SenderError("invalid_recipient_username")
        candidates = []
        for table in ("conversations", "contacts"):
            rows = db.execute("SELECT record_id,data FROM " + table + " WHERE generation=? "
                              "AND json_extract(data,'$.source_username')=? ORDER BY record_id LIMIT 2",
                              (active["generation"], username)).fetchall()
            if len(rows) > 1:
                raise SenderError("recipient_ambiguous")
            if rows:
                recipient = cls._recipient(rows[0], active, contact=table == "contacts")
                if recipient.username != username:
                    raise SenderError("invalid_recipient_record")
                candidates.append(recipient)
        if not candidates:
            raise SenderError("recipient_not_found")
        return candidates[0]  # A real conversation takes precedence over its contact.

    def resolve_username(self, username: str, *, expected_account_id: str) -> Recipient:
        """Independently bind a raw native target to one current archive record.

        This is for the native host boundary; public MCP callers still select
        stored opaque recipient IDs. Names, historical records, and ambiguous raw
        usernames never select a target. All reads share one complete snapshot.
        """
        if (not isinstance(username, str) or not username or len(username) > 512
                or any(ord(char) < 32 for char in username)):
            raise SenderError("invalid_recipient_username")
        with self.connection() as db:
            active = self._active(db)
            if active["account_id"] != expected_account_id:
                raise SenderError("archive_account_mismatch")
            return self._resolve_username(db, active, username)

    def list_recipients(self, query: str = "", limit: int = 50) -> dict:
        if not isinstance(query, str) or len(query) > 256 or "\0" in query:
            raise SenderError("invalid_query")
        if type(limit) is not int or not 1 <= limit <= 200:
            raise SenderError("invalid_limit")
        with self.connection() as db:
            active = self._active(db)
            rows = db.execute("SELECT json_extract(data,'$.source_username') AS username FROM conversations "
                              "WHERE generation=? AND instr(lower(coalesce(json_extract(data,'$.display_name'),'')),lower(?))>0 "
                              "UNION SELECT json_extract(data,'$.source_username') AS username FROM contacts "
                              "WHERE generation=? AND instr(lower(coalesce(json_extract(data,'$.display_name'),'')),lower(?))>0 "
                              "ORDER BY username LIMIT ?", (active["generation"], query, active["generation"], query, limit + 1)).fetchall()
            return {"generation": active["generation"], "items": [self._resolve_username(db, active, row["username"]).public() for row in rows[:limit]],
                    "has_more": len(rows) > limit}
