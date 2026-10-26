"""Independent Mac-record evidence using synthetic reader archives, never app I/O."""
import hashlib
import json
import sqlite3

import pytest

from wechat_sender.backend_protocol import SenderError
from wechat_sender.local_history import observe_local_message, observe_local_message_by_id, text_digest
from test_sender import ACCOUNT, ALICE, BOB, case

TEXT = "Native fixture 中文 🧪\nExact whitespace. "
SERVER = "9007199254740995"  # Must remain exact beyond JavaScript's safe integer.
MESSAGE = "message_" + "1" * 64
CONTACT = "contact_" + "d" * 64


@pytest.fixture
def evidence_case(case):
    archive = case[0]
    with sqlite3.connect(archive.path) as db:
        db.execute("ALTER TABLE generations ADD COLUMN published_at TEXT")
        db.execute("UPDATE generations SET published_at='2026-10-26T10:01:00+00:00'")
        db.execute("CREATE TABLE messages(generation INTEGER,record_id TEXT,data TEXT,conversation_id TEXT,"
                   "sender_id TEXT,type TEXT,timestamp TEXT,time_sort INTEGER,text TEXT,PRIMARY KEY(generation,record_id))")
        db.execute("CREATE INDEX message_timeline ON messages(generation,conversation_id,time_sort,record_id)")
    return archive


def insert(archive, *, generation=2, message_id=MESSAGE, conversation=ALICE,
           server_id=SERVER, local_id="7", text=TEXT, source_account=ACCOUNT,
           timestamp="2026-10-26T10:00:00+00:00", observed="2026-10-26T10:00:30+00:00"):
    record = {"message_id": message_id, "conversation_id": conversation, "sender_id": "contact_" + "a" * 64,
              "source_timestamp": "1793008800", "timestamp_unit": "seconds", "utc_timestamp": timestamp,
              "source_type": "1", "type": "text", "text": text, "parse_status": "ok", "diagnostic_codes": [],
              "source": {"account_id": source_account, "database_id": "fixture-database", "table": "Msg_fixture",
                         "local_id": local_id, "server_id": server_id, "observed_at": observed}}
    with sqlite3.connect(archive.path) as db:
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?)", (generation, message_id, json.dumps(record),
            conversation, record["sender_id"], "text", timestamp, 1793008800, text))


def observe(archive, **changes):
    return observe_local_message(archive, **{"expected_account_id": ACCOUNT, "recipient_id": ALICE,
        "server_id": SERVER, "text_sha256": text_digest(TEXT), **changes})


def observe_id(archive, **changes):
    return observe_local_message_by_id(archive, **{"expected_account_id": ACCOUNT, "recipient_id": ALICE,
        "local_id": 7, "text_sha256": text_digest(TEXT), **changes})


def add_contact(archive, *, username="alice_fixture", generation=2, contact_id=CONTACT):
    record = {"contact_id": contact_id, "source_username": username, "display_name": "Same name"}
    with sqlite3.connect(archive.path) as db:
        db.execute("INSERT INTO contacts VALUES(?,?,?)", (generation, contact_id, json.dumps(record)))


def add_conversation(archive, *, recipient_id=ALICE, username="alice_fixture", generation=2):
    record = {"conversation_id": recipient_id, "source_username": username,
              "kind": "direct", "display_name": "Same name"}
    with sqlite3.connect(archive.path) as db:
        db.execute("INSERT INTO conversations VALUES(?,?,?)", (generation, recipient_id, json.dumps(record)))


def test_exact_record_is_independent_local_evidence_without_delivery_or_text_disclosure(evidence_case):
    insert(evidence_case)
    before = (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns)
    result = observe(evidence_case, after_generation=1, not_before="2026-10-26T10:00:00.500000+00:00")
    assert result["status"] == "observed_in_local_history"
    assert result["message_id"] == MESSAGE and result["server_id"] == SERVER
    assert result["exact_text_match"] is True
    assert result["source"] == "wechat_reader_archive"
    assert result["phone_receipt_evidence"] == result["app_ui_visibility"] == "not_assessed"
    assert TEXT not in json.dumps(result) and ACCOUNT not in json.dumps(result)
    assert "Msg_fixture" not in json.dumps(result) and "fixture-database" not in json.dumps(result)
    after = (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns)
    assert after == before


def test_old_building_and_other_conversation_records_cannot_match(evidence_case):
    insert(evidence_case, generation=1)
    insert(evidence_case, generation=3)
    insert(evidence_case, conversation=BOB)
    result = observe(evidence_case)
    assert result["status"] == "not_observed" and result["diagnostic_code"] == "message_not_in_current_archive"


def test_account_change_and_cross_account_source_are_not_evidence(evidence_case):
    insert(evidence_case, source_account="other-account")
    assert observe(evidence_case)["diagnostic_code"] == "invalid_local_message_record"
    with pytest.raises(SenderError, match="archive_account_mismatch"):
        observe(evidence_case, expected_account_id="other-account")


def test_identical_text_without_exact_server_id_does_not_match(evidence_case):
    insert(evidence_case, server_id="9007199254740996")
    assert observe(evidence_case)["status"] == "not_observed"


def test_exact_server_id_with_changed_text_does_not_match(evidence_case):
    insert(evidence_case, text=TEXT.rstrip())
    assert observe(evidence_case)["diagnostic_code"] == "local_message_content_mismatch"


def test_duplicate_server_records_remain_ambiguous_even_if_text_matches(evidence_case):
    insert(evidence_case)
    insert(evidence_case, message_id="message_" + "2" * 64)
    assert observe(evidence_case)["diagnostic_code"] == "ambiguous_local_message"


def test_stale_snapshot_and_source_time_are_reported_without_claiming_send_failure(evidence_case):
    insert(evidence_case)
    assert observe(evidence_case, after_generation=2)["diagnostic_code"] == "archive_generation_not_advanced"
    assert observe(evidence_case, not_before="2026-10-26T10:02:00Z")["diagnostic_code"] == "archive_snapshot_predates_request"
    assert observe(evidence_case, not_before="2026-10-26T10:00:45Z")["diagnostic_code"] == "local_message_predates_request"


def test_full_uint64_identity_matches_signed_sqlite_representation(evidence_case):
    insert(evidence_case, server_id="-1")
    result = observe(evidence_case, server_id="18446744073709551615")
    assert result["status"] == "observed_in_local_history"
    assert result["server_id"] == "18446744073709551615"


@pytest.mark.parametrize("change,code", [({"server_id": "0"}, "invalid_server_id"),
    ({"server_id": 9007199254740995}, "invalid_server_id"),
    ({"server_id": "18446744073709551616"}, "invalid_server_id"),
    ({"after_generation": True}, "invalid_generation_boundary"),
    ({"not_before": "2026-10-26T10:00:00"}, "invalid_time_boundary"),
    ({"text_sha256": "guess"}, "invalid_expected_text_digest")])
def test_invalid_expectations_fail_before_matching(evidence_case, change, code):
    with pytest.raises(SenderError, match=code):
        observe(evidence_case, **change)


def test_native_local_id_matches_independent_record_and_returns_exact_server_identity(evidence_case):
    insert(evidence_case)
    before = (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns)
    result = observe_id(evidence_case, after_generation=1, not_before="2026-10-26T10:00:00.500000Z")
    assert result["status"] == "observed_in_local_history"
    assert result["local_id"] == 7 and result["server_id"] == SERVER
    assert result["server_id_available"] is True and result["exact_text_match"] is True
    assert result["message_id"] == MESSAGE and result["generation"] == 2
    assert result["phone_receipt_evidence"] == result["app_ui_visibility"] == "not_assessed"
    assert TEXT not in json.dumps(result) and ACCOUNT not in json.dumps(result)
    assert "fixture-database" not in json.dumps(result) and "Msg_fixture" not in json.dumps(result)
    after = (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns)
    assert after == before


def test_local_id_reuse_in_other_generation_or_conversation_cannot_match(evidence_case):
    insert(evidence_case, generation=1)
    insert(evidence_case, generation=3)
    insert(evidence_case, conversation=BOB)
    insert(evidence_case, local_id="8", message_id="message_" + "2" * 64)
    result = observe_id(evidence_case)
    assert result["status"] == "not_observed"
    assert result["diagnostic_code"] == "message_not_in_current_archive" and "server_id" not in result


@pytest.mark.parametrize("change,code", [
    ({"source_account": "other-account"}, "invalid_local_message_record"),
    ({"text": TEXT.rstrip()}, "local_message_content_mismatch"),
    ({"server_id": "not-an-id"}, "invalid_local_message_record"),
])
def test_local_id_match_never_exposes_server_id_from_unverified_record(evidence_case, change, code):
    insert(evidence_case, **change)
    result = observe_id(evidence_case)
    assert result["status"] == "not_observed" and result["diagnostic_code"] == code
    assert "server_id" not in result


def test_local_id_match_requires_current_account_and_fresh_snapshot(evidence_case):
    insert(evidence_case)
    with pytest.raises(SenderError, match="archive_account_mismatch"):
        observe_id(evidence_case, expected_account_id="other-account")
    for changes, code in [({"after_generation": 2}, "archive_generation_not_advanced"),
                          ({"not_before": "2026-10-26T10:02:00Z"}, "archive_snapshot_predates_request"),
                          ({"not_before": "2026-10-26T10:00:45Z"}, "local_message_predates_request")]:
        result = observe_id(evidence_case, **changes)
        assert result["diagnostic_code"] == code and "server_id" not in result


def test_duplicate_local_ids_remain_ambiguous_and_do_not_select_a_server_id(evidence_case):
    insert(evidence_case)
    insert(evidence_case, message_id="message_" + "2" * 64, server_id="123")
    result = observe_id(evidence_case)
    assert result["diagnostic_code"] == "ambiguous_local_message" and "server_id" not in result


@pytest.mark.parametrize("server_id", [None, "0"])
def test_pending_local_record_can_be_observed_without_inventing_server_identity(evidence_case, server_id):
    insert(evidence_case, server_id=server_id)
    result = observe_id(evidence_case)
    assert result["status"] == "observed_in_local_history"
    assert result["server_id_available"] is False and "server_id" not in result


def test_local_lookup_keeps_full_uint64_server_identity_and_uint32_local_id(evidence_case):
    insert(evidence_case, server_id="-1", local_id=str(2**32 - 1))
    result = observe_id(evidence_case, local_id=2**32 - 1)
    assert result["server_id"] == "18446744073709551615"
    assert result["local_id"] == 2**32 - 1


@pytest.mark.parametrize("local_id", [True, 0, -1, 2**32, "7", 7.0])
def test_local_lookup_requires_exact_positive_uint32_native_result(evidence_case, local_id):
    with pytest.raises(SenderError, match="invalid_local_id"):
        observe_id(evidence_case, local_id=local_id)


@pytest.mark.parametrize("observer", [observe, observe_id])
def test_contact_id_matches_actual_conversation_without_inventing_an_id(evidence_case, observer):
    add_contact(evidence_case)
    insert(evidence_case)
    before = (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns)
    result = observer(evidence_case, recipient_id=CONTACT, after_generation=1,
                      not_before="2026-10-26T10:00:00.500000Z")
    assert result["status"] == "observed_in_local_history"
    assert result["recipient_id"] == CONTACT and result["conversation_id"] == ALICE
    assert result["message_id"] == MESSAGE and result["server_id"] == SERVER
    assert result["phone_receipt_evidence"] == result["app_ui_visibility"] == "not_assessed"
    assert "alice_fixture" not in json.dumps(result) and TEXT not in json.dumps(result)
    assert (hashlib.sha256(evidence_case.path.read_bytes()).hexdigest(), evidence_case.path.stat().st_mtime_ns) == before


@pytest.mark.parametrize("observer", [observe, observe_id])
def test_contact_without_conversation_cannot_match_another_recipient_or_building_generation(evidence_case, observer):
    add_contact(evidence_case, username="new_fixture")
    add_conversation(evidence_case, username="new_fixture", generation=3)
    insert(evidence_case)  # Same display name, ID and content do not establish recipient identity.
    insert(evidence_case, generation=3)
    result = observer(evidence_case, recipient_id=CONTACT)
    assert result["status"] == "not_observed"
    assert result["diagnostic_code"] == "recipient_conversation_not_in_current_archive"
    assert "conversation_id" not in result


def test_contact_send_history_becomes_observable_when_a_complete_generation_contains_session(evidence_case):
    add_contact(evidence_case, username="new_fixture")
    assert observe_id(evidence_case, recipient_id=CONTACT)["status"] == "not_observed"
    add_contact(evidence_case, username="new_fixture", generation=3)
    add_conversation(evidence_case, username="new_fixture", generation=3)
    insert(evidence_case, generation=3)
    with sqlite3.connect(evidence_case.path) as db:
        db.execute("UPDATE generations SET state='complete' WHERE generation=3")
        db.execute("UPDATE archive_state SET active_generation=3")
    result = observe_id(evidence_case, recipient_id=CONTACT, after_generation=2,
                        not_before="2026-10-26T10:00:00Z")
    assert result["status"] == "observed_in_local_history"
    assert result["generation"] == 3 and result["conversation_id"] == ALICE


def test_contact_mapping_rejects_ambiguous_actual_conversations(evidence_case):
    add_contact(evidence_case)
    add_conversation(evidence_case, recipient_id="conversation_" + "e" * 64)
    insert(evidence_case)
    with pytest.raises(SenderError, match="recipient_ambiguous"):
        observe_id(evidence_case, recipient_id=CONTACT)


def test_contact_mapping_requires_existing_valid_contact_record(evidence_case):
    insert(evidence_case)
    with pytest.raises(SenderError, match="recipient_not_found"):
        observe_id(evidence_case, recipient_id=CONTACT)
    add_contact(evidence_case)
    with sqlite3.connect(evidence_case.path) as db:
        db.execute("UPDATE contacts SET data=json_set(data,'$.contact_id',?)", ("contact_" + "e" * 64,))
    with pytest.raises(SenderError, match="invalid_recipient_record"):
        observe_id(evidence_case, recipient_id=CONTACT)


@pytest.mark.parametrize("change,code", [
    ({"source_account": "other-account"}, "invalid_local_message_record"),
    ({"text": TEXT.rstrip()}, "local_message_content_mismatch"),
    ({"observed": "2026-10-26T09:00:00Z"}, "local_message_predates_request"),
])
def test_contact_mapping_preserves_account_exact_text_and_freshness_checks(evidence_case, change, code):
    add_contact(evidence_case)
    insert(evidence_case, **change)
    result = observe_id(evidence_case, recipient_id=CONTACT, not_before="2026-10-26T10:00:00Z")
    assert result["status"] == "not_observed" and result["diagnostic_code"] == code
    assert "server_id" not in result
