"""Unit and MCP-contract tests use a mock transport. They do not send WeChat messages."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sqlite3

import pytest
from mcp import Client

from wechat_sender.archive import ArchiveReader
from wechat_sender.backend_protocol import SenderError
from wechat_sender.ledger import Ledger, fingerprint
from wechat_sender.server import SendService, create_server

ALICE = "conversation_" + "a" * 64
BOB = "conversation_" + "b" * 64
GROUP = "conversation_" + "c" * 64
ABSENT = "conversation_" + "f" * 64
ACCOUNT = "fixture-account-uuid"
CONTACT_ONLY = "contact_" + "d" * 64


def add_contact(archive, *, contact_id=CONTACT_ONLY, username="contact_only_fixture", generation=2,
                name="Contact without a chat"):
    record = {"contact_id": contact_id, "source_username": username, "display_name": name}
    with sqlite3.connect(archive.path) as db:
        db.execute("INSERT INTO contacts VALUES(?,?,?)", (generation, contact_id, json.dumps(record)))


class MockBackend:
    """Only a test double; never imported by package code or production CLI."""
    def __init__(self):
        self.ready = True
        self.verified = True
        self.account_id = ACCOUNT
        self.calls = []
        self.delay = 0
        self.result = {"status": "submitted"}
        self.error = None

    async def status(self):
        return {"ready": self.ready, "identity_verified": self.verified, "account_id": self.account_id,
                "diagnostic_code": "backend_not_ready" if not self.ready else None}

    async def send_text(self, target_username, text, operation_id):
        self.calls.append((target_username, text, operation_id))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def case(tmp_path):
    archive_path = tmp_path / "archive.sqlite3"
    db = sqlite3.connect(archive_path)
    db.executescript("""
        PRAGMA user_version=2;
        CREATE TABLE archive_state(singleton INTEGER,active_generation INTEGER);
        CREATE TABLE generations(generation INTEGER,account_id TEXT,state TEXT);
        CREATE TABLE conversations(generation INTEGER,record_id TEXT,data TEXT,PRIMARY KEY(generation,record_id));
        CREATE TABLE contacts(generation INTEGER,record_id TEXT,data TEXT,PRIMARY KEY(generation,record_id));
        INSERT INTO archive_state VALUES(1,2);
    """)
    db.executemany("INSERT INTO generations VALUES(?,?,?)", [(1, ACCOUNT, "complete"), (2, ACCOUNT, "complete"), (3, ACCOUNT, "building")])
    values = [(ALICE, "alice_fixture", "direct", "Same name"), (BOB, "bob_fixture", "direct", "Same name"),
              (GROUP, "group_fixture@chatroom", "group", "Manufacturer")]
    for cid, username, kind, name in values:
        record = {"conversation_id": cid, "source_username": username, "kind": kind, "display_name": name}
        db.execute("INSERT INTO conversations VALUES(2,?,?)", (cid, json.dumps(record)))
    db.execute("INSERT INTO conversations VALUES(1,?,?)", (ABSENT, json.dumps({"conversation_id": ABSENT,
               "source_username": "stale_fixture", "kind": "direct", "display_name": "Old"})))
    db.commit()
    db.close()
    os.chmod(archive_path, 0o600)
    archive = ArchiveReader(archive_path)
    ledger = Ledger(tmp_path / "sender-state" / "outbox.sqlite3")
    backend = MockBackend()
    return archive, ledger, backend, SendService(archive, ledger, backend)


def run(awaitable):
    return asyncio.run(awaitable)


def test_resolution_uses_exact_opaque_id_and_preserves_duplicate_names(case):
    archive, _, backend, service = case
    recipients = service.list_recipients("Same")
    assert [r["recipient_id"] for r in recipients["items"]] == [ALICE, BOB]
    assert all("source_username" not in r and "username" not in r for r in recipients["items"])
    result = run(service.send_text(BOB, "Hello", "request-1"))
    assert result["status"] == "submitted"
    assert backend.calls[0][:2] == ("bob_fixture", "Hello")
    assert archive.resolve(GROUP).username == "group_fixture@chatroom"


def test_contact_without_a_session_is_listed_resolved_and_sendable_by_stored_id(case):
    archive, _, backend, service = case
    add_contact(archive)
    listed = service.list_recipients("without a chat")["items"]
    assert listed == [{"recipient_id": CONTACT_ONLY, "display_name": "Contact without a chat",
                       "kind": "direct", "generation": 2}]
    result = run(service.send_text(CONTACT_ONLY, "First chat fixture", "first-contact-intent"))
    assert result["status"] == "submitted"
    assert backend.calls[0][:2] == ("contact_only_fixture", "First chat fixture")
    assert archive.resolve_username("contact_only_fixture", expected_account_id=ACCOUNT).recipient_id == CONTACT_ONLY


def test_contact_and_conversation_aliases_deduplicate_without_losing_contact_name_search(case):
    archive, _, _, service = case
    alias = "contact_" + "e" * 64
    add_contact(archive, contact_id=alias, username="alice_fixture", name="Alice address book alias")
    all_items = service.list_recipients()["items"]
    assert len(all_items) == 3 and {row["recipient_id"] for row in all_items} == {ALICE, BOB, GROUP}
    assert service.list_recipients("address book")["items"][0]["recipient_id"] == ALICE
    assert archive.resolve(alias).recipient_id == alias
    assert archive.resolve_username("alice_fixture", expected_account_id=ACCOUNT).recipient_id == ALICE


def test_stale_and_building_contact_records_are_not_new_recipients(case):
    archive, _, _, service = case
    add_contact(archive, generation=1)
    add_contact(archive, generation=3)
    assert service.list_recipients("without a chat")["items"] == []
    with pytest.raises(SenderError, match="recipient_not_found"):
        archive.resolve(CONTACT_ONLY)
    with pytest.raises(SenderError, match="recipient_not_found"):
        archive.resolve_username("contact_only_fixture", expected_account_id=ACCOUNT)


def test_duplicate_contact_identity_is_ambiguous_even_for_an_exact_stored_id(case):
    archive = case[0]
    add_contact(archive)
    add_contact(archive, contact_id="contact_" + "e" * 64)
    with pytest.raises(SenderError, match="recipient_ambiguous"):
        archive.resolve(CONTACT_ONLY)
    with pytest.raises(SenderError, match="recipient_ambiguous"):
        archive.resolve_username("contact_only_fixture", expected_account_id=ACCOUNT)


def test_contact_recipient_is_accepted_by_actual_mcp_tool_schema(case):
    archive, _, backend, service = case
    add_contact(archive)
    async def scenario():
        async with Client(create_server(service)) as client:
            return await client.call_tool("send_text", {"recipient_id": CONTACT_ONLY,
                "text": "Schema fixture", "request_id": "contact-schema"})
    result = run(scenario())
    assert result.is_error is False and result.structured_content["status"] == "submitted"
    assert backend.calls[0][0] == "contact_only_fixture"


@pytest.mark.parametrize("recipient,error", [("Same name", "invalid_recipient_id"), (ABSENT, "recipient_not_found")])
def test_missing_or_name_recipient_never_dispatches(case, recipient, error):
    _, _, backend, service = case
    with pytest.raises(SenderError, match=error):
        run(service.send_text(recipient, "Hello", "missing"))
    assert backend.calls == []


@pytest.mark.parametrize("change,error", [("not_ready", "backend_not_ready"), ("unverified", "identity_not_verified"),
                                         ("wrong_account", "backend_account_mismatch")])
def test_unready_or_unverified_backend_never_claims_or_dispatches(case, change, error):
    _, ledger, backend, service = case
    if change == "not_ready":
        backend.ready = False
    elif change == "unverified":
        backend.verified = False
    else:
        backend.account_id = "other-account"
    with pytest.raises(SenderError, match=error):
        run(service.send_text(ALICE, "Hello", "blocked"))
    assert backend.calls == []
    assert ledger.lookup("blocked", fingerprint(ALICE, "Hello")) is None


def test_request_id_repeat_does_not_dispatch_again_even_if_backend_offline(case):
    _, _, backend, service = case
    first = run(service.send_text(ALICE, "Exact text", "one-intent"))
    backend.ready = False
    replay = run(service.send_text(ALICE, "Exact text", "one-intent"))
    assert replay["operation_id"] == first["operation_id"]
    assert replay["status"] == "submitted" and replay["replayed"]
    assert len(backend.calls) == 1
    with pytest.raises(SenderError, match="request_id_reused_with_different_payload"):
        run(service.send_text(ALICE, "Changed text", "one-intent"))
    with pytest.raises(SenderError, match="request_id_reused_with_different_payload"):
        run(service.send_text(BOB, "Exact text", "one-intent"))
    assert len(backend.calls) == 1


@pytest.mark.parametrize("failure", ["timeout", "exception", "invalid_return"])
def test_uncertain_result_persists_and_never_retries(case, failure):
    archive, ledger, backend, service = case
    if failure == "timeout":
        backend.delay = 0.05
        service.submission_timeout = 0.001
    elif failure == "exception":
        backend.error = RuntimeError("private data must not appear")
    else:
        backend.result = {"status": "success", "private": "hidden"}
    result = run(service.send_text(ALICE, "Sensitive outgoing body", "uncertain"))
    assert result["status"] == "outcome_unknown"
    assert "private" not in json.dumps(result)
    restarted = SendService(archive, Ledger(ledger.path), MockBackend())
    replay = run(restarted.send_text(ALICE, "Sensitive outgoing body", "uncertain"))
    assert replay["replayed"] and replay["status"] == "outcome_unknown"
    assert restarted.backend.calls == []
    assert restarted.list_outbox(request_id="uncertain")["items"][0]["text"] == "Sensitive outgoing body"
    assert ledger.path.stat().st_mode & 0o077 == 0


def test_crash_after_durable_claim_does_not_allow_dispatch(case):
    archive, ledger, backend, _ = case
    operation, _ = ledger.claim("crashed", fingerprint(ALICE, "Message"), ACCOUNT, ALICE)
    restarted = SendService(archive, Ledger(ledger.path), backend)
    result = run(restarted.send_text(ALICE, "Message", "crashed"))
    assert result["operation_id"] == operation
    assert result["status"] == "outcome_unknown"
    assert backend.calls == []


def test_concurrent_duplicate_calls_only_submit_once(case):
    _, _, backend, service = case
    backend.delay = 0.02
    async def scenario():
        return await asyncio.gather(*(service.send_text(ALICE, "Hello", "concurrent") for _ in range(10)))
    results = run(scenario())
    assert len(backend.calls) == 1
    assert len({r["operation_id"] for r in results}) == 1
    assert sum(r["status"] == "submitted" for r in results) == 1
    assert all(r["status"] in ("submitted", "outcome_unknown") for r in results)
    assert run(service.send_text(ALICE, "Hello", "concurrent"))["status"] == "submitted"


def test_atomic_claim_across_separate_connections(case):
    _, ledger, _, _ = case
    def claim(_):
        return Ledger(ledger.path).claim("cross-process-claim", fingerprint(ALICE, "Hello"), ACCOUNT, ALICE)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(claim, range(16)))
    assert sum(operation is not None for operation, _ in results) == 1


def test_archive_is_read_only_and_missing_archive_not_created(case, tmp_path):
    archive, _, _, service = case
    before = hashlib.sha256(archive.path.read_bytes()).hexdigest()
    mtime = archive.path.stat().st_mtime_ns
    service.list_recipients()
    archive.resolve(ALICE)
    run(service.send_text(ALICE, "Message", "read-only-check"))
    assert hashlib.sha256(archive.path.read_bytes()).hexdigest() == before
    assert archive.path.stat().st_mtime_ns == mtime
    with pytest.raises(SenderError, match="archive_query_failed"):
        with archive.connection() as db:
            db.execute("DELETE FROM conversations")
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(SenderError, match="archive_unavailable"):
        ArchiveReader(missing).account_id()
    assert not missing.exists()


def test_mcp_contract_marks_send_as_mutation_and_rejects_unknown_arguments(case):
    _, _, backend, service = case
    async def scenario():
        async with Client(create_server(service)) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            assert set(tools) == {"sender_status", "list_recipients", "list_outbox", "get_send_status", "send_text"}
            assert tools["send_text"].annotations.read_only_hint is False
            assert tools["send_text"].annotations.open_world_hint is True
            assert tools["send_text"].annotations.idempotent_hint is True
            assert tools["list_recipients"].annotations.read_only_hint is True
            assert tools["list_outbox"].annotations.read_only_hint is True
            for name, arguments in [("send_text", {"recipient_id": ALICE, "text": "x", "request_id": "contract", "override": True}),
                                    ("send_text", {"recipient_id": "name", "text": "x", "request_id": "contract"}),
                                    ("list_recipients", {"limit": True})]:
                result = await client.call_tool(name, arguments)
                assert result.is_error
                assert result.structured_content == {"error": "invalid_arguments"}
            state = await client.call_tool("sender_status", {})
            assert state.structured_content["ready"] is True
            response = await client.call_tool("send_text", {"recipient_id": ALICE, "text": "Contract fixture", "request_id": "contract"})
            assert not response.is_error
            assert response.structured_content["status"] == "submitted"
            audit = await client.call_tool("list_outbox", {"request_id": "contract"})
            assert audit.structured_content["source"] == "sender_outbox"
            assert audit.structured_content["items"][0]["text"] == "Contract fixture"
    run(scenario())
    assert len(backend.calls) == 1


def test_backend_unavailability_diagnostic_survives_missing_account_identity(case):
    _, _, backend, service = case
    backend.ready = False
    backend.verified = False
    backend.account_id = None
    assert run(service.sender_status()) == {"ready": False, "identity_verified": False, "diagnostic_code": "backend_not_ready"}


def test_text_limit_matches_native_utf8_bytes_before_dispatch(case):
    _, _, backend, service = case
    run(service.send_text(ALICE, "é" * 2048, "exact-byte-limit"))
    with pytest.raises(SenderError, match="invalid_text"):
        run(service.send_text(ALICE, "é" * 2048 + "a", "over-byte-limit"))
    assert len(backend.calls) == 1


def test_rejected_submission_is_terminal_for_same_request(case):
    _, _, backend, service = case
    backend.result = {"status": "rejected", "diagnostic_code": "native_session_not_ready"}
    first = run(service.send_text(ALICE, "Message", "reject-1"))
    backend.result = {"status": "submitted"}
    second = run(service.send_text(ALICE, "Message", "reject-1"))
    assert first["status"] == second["status"] == "rejected"
    assert len(backend.calls) == 1


def test_cancelled_caller_cannot_retry_a_committed_submission(case):
    archive, ledger, backend, service = case
    backend.delay = 1
    async def scenario():
        task = asyncio.create_task(service.send_text(ALICE, "Message", "cancel-1"))
        while not backend.calls:
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    run(scenario())
    restarted_backend = MockBackend()
    restarted = SendService(archive, Ledger(ledger.path), restarted_backend)
    result = run(restarted.send_text(ALICE, "Message", "cancel-1"))
    assert result["status"] == "outcome_unknown"
    assert restarted_backend.calls == []
