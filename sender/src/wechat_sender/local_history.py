"""Read-only evidence that an exact native send appears in the Mac reader archive.

This is independent of sender_outbox. It never imports, refreshes, inserts,
reconciles, or deletes records, and never changes a submission result. A match
is evidence of a local record, not phone delivery, app UI state, or read receipt.
"""
from datetime import UTC, datetime
import hashlib
import json
import re

from .archive import ArchiveReader, MAX_RECORD_BYTES, RECIPIENT_PATTERN
from .backend_protocol import SenderError

MESSAGE_PATTERN = r"message_[0-9a-f]{64}"


def text_digest(text: str) -> str:
    """Digest exact UTF-8 text: no whitespace, Unicode, or line-ending folding."""
    if not isinstance(text, str):
        raise SenderError("invalid_expected_text")
    try:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise SenderError("invalid_expected_text") from None


def canonical_server_id(value: str) -> str:
    """Match uint64 wire IDs against their SQLite signed-int64 representation."""
    if not isinstance(value, str) or not re.fullmatch(r"-?[0-9]{1,20}", value):
        raise SenderError("invalid_server_id")
    number = int(value)
    if number == 0 or number < -(1 << 63) or number >= 1 << 64:
        raise SenderError("invalid_server_id")
    return str(number if number > 0 else number + (1 << 64))


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp needs timezone")
    return result.astimezone(UTC)


def observe_local_message(archive: ArchiveReader, *, expected_account_id: str,
                          recipient_id: str, server_id: str, text_sha256: str,
                          not_before: str | None = None,
                          after_generation: int | None = None) -> dict:
    """Return only redacted evidence for one exact expected local text message.

    `not_before` bounds both the archive observation and native message time;
    native timestamps have one-second precision. `after_generation` can require
    a refresh beyond a baseline captured before the trial. Archive absence or
    staleness is never evidence that a send failed. SenderError reports invalid
    expectations, unavailable archives, or unsupported schemas.
    """
    return _observe(archive, expected_account_id=expected_account_id, recipient_id=recipient_id,
                    server_id=canonical_server_id(server_id), local_id=None, text_sha256=text_sha256,
                    not_before=not_before, after_generation=after_generation)


def observe_local_message_by_id(archive: ArchiveReader, *, expected_account_id: str,
                                recipient_id: str, local_id: int, text_sha256: str,
                                not_before: str | None = None,
                                after_generation: int | None = None) -> dict:
    """Independently match a native send result's local ID to an archive record.

    Require the caller's exact native result ID, current account, recipient,
    and text digest. Local IDs are not globally unique: multiple matching rows
    are ambiguous, even if their text agrees. A nonzero server ID is returned
    only from a fully validated, unique record; a pending local record may have
    no server ID. Nothing is written, and native/ledger terminal states do not
    change. Contact IDs resolve to an actual conversation in the same archive
    snapshot; a contact without an observed conversation cannot establish history.
    Optional freshness bounds have the same meaning as server-ID lookup.
    """
    if type(local_id) is not int or not 0 < local_id < 2**32:
        raise SenderError("invalid_local_id")
    return _observe(archive, expected_account_id=expected_account_id, recipient_id=recipient_id,
                    server_id=None, local_id=local_id, text_sha256=text_sha256,
                    not_before=not_before, after_generation=after_generation)


def _observe(archive: ArchiveReader, *, expected_account_id: str, recipient_id: str,
             server_id: str | None, local_id: int | None, text_sha256: str,
             not_before: str | None, after_generation: int | None) -> dict:
    if not isinstance(expected_account_id, str) or not expected_account_id:
        raise SenderError("invalid_expected_account")
    if not isinstance(recipient_id, str) or not re.fullmatch(RECIPIENT_PATTERN, recipient_id):
        raise SenderError("invalid_recipient_id")
    if not isinstance(text_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", text_sha256):
        raise SenderError("invalid_expected_text_digest")
    if after_generation is not None and (type(after_generation) is not int or not 0 <= after_generation < 2**63):
        raise SenderError("invalid_generation_boundary")
    try:
        boundary = _time(not_before) if not_before is not None else None
    except (ValueError, OverflowError):
        raise SenderError("invalid_time_boundary") from None
    canonical = server_id
    with archive.connection() as db:
        active = archive._active(db)
        if active["account_id"] != expected_account_id:
            raise SenderError("archive_account_mismatch")
        generation = active["generation"]
        publication = db.execute("SELECT published_at FROM generations WHERE generation=?", (generation,)).fetchone()[0]
        base = {"source": "wechat_reader_archive", "generation": generation, "published_at": publication,
                "recipient_id": recipient_id,
                "phone_receipt_evidence": "not_assessed", "app_ui_visibility": "not_assessed"}
        if canonical is not None:
            base["server_id"] = canonical
        else:
            base["local_id"] = local_id
        def absent(code):
            return base | {"status": "not_observed", "diagnostic_code": code}
        if after_generation is not None and generation <= after_generation:
            return absent("archive_generation_not_advanced")
        if boundary is not None:
            try:
                if _time(publication) < boundary:
                    return absent("archive_snapshot_predates_request")
            except (ValueError, OverflowError):
                return absent("archive_publication_time_unavailable")
        conversation_id = recipient_id
        if recipient_id.startswith("contact_"):
            recipient = archive._resolve_id(db, active, recipient_id)
            conversation = archive._resolve_username(db, active, recipient.username)
            if not conversation.recipient_id.startswith("conversation_"):
                return absent("recipient_conversation_not_in_current_archive")
            conversation_id = conversation.recipient_id
            base["conversation_id"] = conversation_id
        if canonical is not None:
            signed = str(int(canonical) - (1 << 64)) if int(canonical) >= 1 << 63 else canonical
            predicate, identifiers = "json_extract(data,'$.source.server_id') IN (?,?)", (canonical, signed)
        else:
            predicate, identifiers = "json_extract(data,'$.source.local_id') IN (?,?)", (str(local_id), local_id)
        rows = db.execute("SELECT record_id,data,conversation_id,type,timestamp,text FROM messages "
                          "WHERE generation=? AND conversation_id=? AND " + predicate +
                          " ORDER BY record_id LIMIT 2", (generation, conversation_id, *identifiers)).fetchall()
        if not rows:
            return absent("message_not_in_current_archive")
        if len(rows) != 1:
            return absent("ambiguous_local_message")
        row = rows[0]
        try:
            if not isinstance(row["data"], str) or len(row["data"].encode("utf-8")) > MAX_RECORD_BYTES:
                return absent("invalid_local_message_record")
            record = json.loads(row["data"])
            source = record["source"]
            if (not re.fullmatch(MESSAGE_PATTERN, row["record_id"])
                    or record["message_id"] != row["record_id"]
                    or record["conversation_id"] != conversation_id or source["account_id"] != expected_account_id
                    or record["type"] != "text" or row["type"] != "text"
                    or record.get("parse_status") not in {"ok", "partial"}
                    or not isinstance(record["text"], str) or record["text"] != row["text"]
                    or record["utc_timestamp"] != row["timestamp"]):
                return absent("invalid_local_message_record")
            if canonical is not None:
                if canonical_server_id(source["server_id"]) != canonical:
                    return absent("invalid_local_message_record")
                observed_server = canonical
            else:
                source_local = source["local_id"]
                if (type(source_local) is int and source_local == local_id
                        or isinstance(source_local, str) and source_local == str(local_id)):
                    # The reader uses strings for 64-bit server IDs. Zero/None
                    # denotes a local record without server identity yet.
                    observed_server = (None if source.get("server_id") in (None, "0")
                                       else canonical_server_id(source["server_id"]))
                else:
                    return absent("invalid_local_message_record")
            if text_digest(record["text"]) != text_sha256:
                return absent("local_message_content_mismatch")
            message_time, observed_time = _time(record["utc_timestamp"]), _time(source["observed_at"])
            if boundary is not None and (observed_time < boundary or message_time < boundary.replace(microsecond=0)):
                return absent("local_message_predates_request")
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, SenderError):
            return absent("invalid_local_message_record")
        evidence = {"status": "observed_in_local_history", "diagnostic_code": None,
                       "message_id": row["record_id"], "message_timestamp": record["utc_timestamp"],
                       "source_observed_at": source["observed_at"], "exact_text_match": True}
        if local_id is not None:
            evidence["server_id_available"] = observed_server is not None
            if observed_server is not None:
                evidence["server_id"] = observed_server
        return base | evidence
