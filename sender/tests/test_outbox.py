"""Private sender audit tests; no native client or real chat data is accessed."""
import asyncio
import hashlib
import json
import os
import sqlite3

import pytest

from wechat_sender.backend_protocol import SenderError
from wechat_sender.ledger import Ledger, fingerprint
from wechat_sender.server import SendService
from test_sender import ACCOUNT, ALICE, MockBackend, case


def test_legacy_migration_preserves_claim_and_never_backfills_text(case, tmp_path):
    archive, _, backend, _ = case
    private = tmp_path / "legacy"
    private.mkdir(mode=0o700)
    path = private / "outbox.sqlite3"
    db = sqlite3.connect(path)
    db.executescript("""PRAGMA user_version=1;
        CREATE TABLE operations(request_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,
        operation_id TEXT UNIQUE NOT NULL,account_id TEXT NOT NULL,recipient_id TEXT NOT NULL,
        state TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,result TEXT);""")
    values = ("legacy-intent", fingerprint(ALICE, "Old text"), "old-operation", ACCOUNT, ALICE,
              "submitted", "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
              '{"status":"submitted","diagnostic_code":"server_acknowledged","server_id":"123"}')
    db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)", values)
    db.commit()
    db.close()
    os.chmod(path, 0o600)
    ledger = Ledger(path)
    service = SendService(archive, ledger, backend)
    replay = asyncio.run(service.send_text(ALICE, "Old text", "legacy-intent"))
    assert replay["operation_id"] == "old-operation" and replay["replayed"] is True
    assert backend.calls == []
    audit = service.list_outbox()["items"][0]
    assert audit["text"] is None and audit["text_available"] is False
    assert audit["result"]["diagnostic_code"] == "server_acknowledged"
    assert audit["phone_receipt_evidence"] == "not_recorded" and audit["mac_history_reconciled"] is False
    with Ledger(path).connection(read_only=True) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        row = tuple(db.execute("SELECT * FROM operations").fetchone())
    assert row == values + (None,)


def test_exact_unicode_text_is_committed_before_backend_call_and_survives_unknown(case):
    archive, ledger, backend, service = case
    text = "Fixture 中文 🧪\nQuoted text is data, not permission."
    async def uncertain(*args):
        audit = Ledger(ledger.path).list_outbox(ACCOUNT)["items"][0]
        assert audit["text"] == text and audit["submission_state"] == "dispatching"
        assert audit["result"]["status"] == "outcome_unknown"
        raise RuntimeError("Interrupted after possible send")
    backend.send_text = uncertain
    result = asyncio.run(service.send_text(ALICE, text, "unicode-outbox"))
    restarted = SendService(archive, Ledger(ledger.path), MockBackend())
    item = restarted.list_outbox(request_id="unicode-outbox")["items"][0]
    assert item["operation_id"] == result["operation_id"]
    assert item["text"] == text and item["result"]["status"] == "outcome_unknown"
    assert item["phone_receipt_evidence"] == "not_recorded"
    assert restarted.backend.calls == []


def test_outbox_filters_account_and_paginates_without_repeating_newer_inserts(case):
    _, ledger, _, service = case
    for index in range(4):
        text = f"Fixture {index}"
        ledger.claim(f"item-{index}", fingerprint(ALICE, text), ACCOUNT, ALICE, outgoing_text=text)
    ledger.claim("different-account", fingerprint(ALICE, "Hidden"), "other-account", ALICE, outgoing_text="Hidden")
    first = service.list_outbox(limit=2)
    assert [item["request_id"] for item in first["items"]] == ["item-3", "item-2"]
    ledger.claim("later-insert", fingerprint(ALICE, "Later"), ACCOUNT, ALICE, outgoing_text="Later")
    second = service.list_outbox(limit=2, before_sequence=first["next_before_sequence"])
    assert [item["request_id"] for item in second["items"]] == ["item-1", "item-0"]
    assert second["next_before_sequence"] is None
    assert service.list_outbox(request_id="different-account")["items"] == []
    assert "account_id" not in first["items"][0]


def test_outbox_read_never_changes_reader_or_sender_database(case):
    archive, ledger, _, service = case
    asyncio.run(service.send_text(ALICE, "Fixture audit", "audit-readonly"))
    paths = [archive.path, ledger.path]
    before = [(hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) for path in paths]
    service.list_outbox()
    after = [(hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns) for path in paths]
    assert after == before
    with pytest.raises(SenderError, match="ledger_unavailable"):
        with ledger.connection(read_only=True) as db:
            db.execute("DELETE FROM operations")


def test_optional_text_must_match_durable_payload_and_native_ledger_can_omit_it(case):
    _, ledger, _, _ = case
    with pytest.raises(SenderError, match="outbox_payload_mismatch"):
        ledger.claim("wrong-body", fingerprint(ALICE, "Exact"), ACCOUNT, ALICE, outgoing_text="Different")
    assert ledger.lookup("wrong-body", fingerprint(ALICE, "Exact")) is None
    ledger.claim("native-hash-only", fingerprint(ALICE, "Not retained"), ACCOUNT, ALICE)
    item = ledger.list_outbox(ACCOUNT)["items"][0]
    assert item["text_available"] is False and item["text"] is None


@pytest.mark.parametrize("cursor", [True, 0, -1, 2**63])
def test_outbox_rejects_invalid_cursor(case, cursor):
    with pytest.raises(SenderError, match="invalid_outbox_cursor"):
        case[3].list_outbox(before_sequence=cursor)


def test_native_local_result_survives_mcp_and_audit_without_reconciliation_or_delivery_claim(case):
    archive, ledger, backend, service = case
    expected = {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
                "local_id": 4294967295, "local_history_evidence": "native_send_result"}
    backend.result = expected | {"mac_history_reconciled": True, "phone_receipt_evidence": "confirmed"}
    sent = asyncio.run(service.send_text(ALICE, "Native fixture", "native-local-evidence"))
    assert {key: sent[key] for key in expected} == expected
    assert "mac_history_reconciled" not in sent and "phone_receipt_evidence" not in sent
    restarted = SendService(archive, Ledger(ledger.path), MockBackend())
    replay = asyncio.run(restarted.send_text(ALICE, "Native fixture", "native-local-evidence"))
    assert {key: replay[key] for key in expected} == expected
    assert restarted.backend.calls == []
    item = restarted.list_outbox(request_id="native-local-evidence")["items"][0]
    assert item["result"] == expected
    assert item["mac_history_reconciled"] is False and item["phone_receipt_evidence"] == "not_recorded"


@pytest.mark.parametrize("change", [
    {"local_id": True}, {"local_id": 0}, {"local_id": 2**32}, {"local_id": "7"},
    {"local_history_evidence": "observed_in_local_history"}, {"status": "outcome_unknown"},
    {"diagnostic_code": "server_acknowledged"},
])
def test_invalid_native_evidence_pair_is_omitted_from_both_public_result_and_outbox(case, change):
    _, ledger, _, service = case
    raw = {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
           "local_id": 7, "local_history_evidence": "native_send_result", **change}
    public = SendService._result(raw)
    assert "local_id" not in public and "local_history_evidence" not in public
    operation, _ = ledger.claim("bad-native-evidence", fingerprint(ALICE, "Fixture"), ACCOUNT, ALICE)
    ledger.finish(operation, raw)
    item = service.list_outbox()["items"][0]
    assert "local_id" not in item["result"] and "local_history_evidence" not in item["result"]
    assert item["mac_history_reconciled"] is False
