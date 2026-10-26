"""Production-boundary regressions; synthetic archives and mocked native APIs only.

The socket tests use a private local fixture peer. No test opens WeChat or sends
messages. Native result fixtures establish protocol handling, not native proof.
"""
import asyncio
import json
import sqlite3
from types import SimpleNamespace

import pytest

from wechat_sender.backend import NativeBackend
from wechat_sender.backend_protocol import SenderError
from wechat_sender.deployment import DEPLOYMENT_FINGERPRINT, fingerprint as deployment_fingerprint
from wechat_sender.ledger import Ledger, fingerprint
from wechat_sender.native_host import NativeRuntime
from wechat_sender.supervisor import ensure_started, stop_host
from test_native_boundary import (host_request, mock_runtime, native_pipeline_completion as raw_completion,
                                  script_load_case, socket_state)
from test_sender import ACCOUNT, ALICE, case
from test_supervisor import fixture_profile, fixture_socket, state_response


def completion(local_id=7):
    return {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
            "local_id": local_id, "local_history_evidence": "native_send_result"}


def native_pipeline_completion(**changes):
    return raw_completion(local_id=7, **changes)


def pipeline(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    runtime.profile = {"native_pipeline": {"enabled": True}}
    runtime.args.legacy_research = False
    exports = runtime.script.exports_sync
    def sendnative(target, text, operation, sequence):
        runtime.calls.append(("sendnative", target, text, operation, sequence))
        return native_pipeline_completion(operation_known=True, dispatch_sequence=sequence)
    def acknowledge(operation, sequence):
        record = runtime.journal.record(operation, account_id=ACCOUNT)
        assert record["state"] != "dispatching", "Never release before committing evidence"
        assert record["sequence"] == sequence
        runtime.calls.append(("ack", operation, sequence))
        return {"acknowledged": True}
    exports.sendnative, exports.acknowledge = sendnative, acknowledge
    return runtime


@pytest.mark.parametrize("asset", ["server.py", "native_pipeline_sender.js", "native_pipeline.cpp", "native_pipeline.dylib"])
def test_deployment_identity_covers_python_and_native_assets(tmp_path, asset):
    (tmp_path / asset).write_bytes(b"fixture-v1")
    first = deployment_fingerprint(tmp_path)
    (tmp_path / "README.md").write_text("Documentation is not executable code")
    assert deployment_fingerprint(tmp_path) == first
    (tmp_path / asset).write_bytes(b"fixture-v2")
    assert deployment_fingerprint(tmp_path) != first


@pytest.mark.parametrize("was_ready", [False, True])
def test_upgrade_refuses_reuse_without_restarting_existing_host(socket_state, fixture_profile, monkeypatch, was_ready):
    monkeypatch.setattr("wechat_sender.supervisor.subprocess.Popen", lambda *a, **k: pytest.fail("Never auto-restart an old host"))
    async def scenario():
        response = state_response(fixture_profile)
        response.update(ready=was_ready, identity_verified=True, account_id=ACCOUNT)
        response["host"]["deployment_fingerprint"] = "old-deployment"
        requests = []
        server = await fixture_socket(socket_state, response, requests)
        async with server:
            backend = NativeBackend(reader_archive=socket_state / "fixture", state=socket_state)
            status = await backend.status()
            assert not status["ready"] and not status["identity_verified"]
            assert status["diagnostic_code"] == "sender_upgrade_requires_restart"
            assert status["host"]["managed"] is True
            with pytest.raises(SenderError, match="sender_upgrade_requires_restart"):
                await ensure_started(state=socket_state, reader_archive=socket_state / "fixture", profile=fixture_profile)
            # Stop remains available across upgrades; no arbitrary OS signal.
            await stop_host(state=socket_state, reader_archive=socket_state / "fixture")
        assert requests[-1]["method"] == "stop"
        assert "expected_deployment" not in requests[-1]
    asyncio.run(scenario())


@pytest.mark.parametrize("enabled", [None, False, 1, "true"])
def test_production_start_requires_literal_pipeline_opt_in_before_launch(socket_state, fixture_profile, monkeypatch, enabled):
    fixture_profile.write_text(json.dumps({"native_pipeline": {"enabled": enabled}}))
    monkeypatch.setattr("wechat_sender.supervisor.subprocess.Popen", lambda *a, **k: pytest.fail("Disabled pipeline must not launch"))
    with pytest.raises(SenderError, match="native_pipeline_not_enabled"):
        asyncio.run(ensure_started(state=socket_state, reader_archive=socket_state / "fixture", profile=fixture_profile))
    assert not (socket_state / "native-host.log").exists()


def test_retired_transport_requires_explicit_research_mode(script_load_case):
    runtime, _, calls, _ = script_load_case
    runtime.profile = {"native_pipeline": {"enabled": False}}
    runtime.args.legacy_research = False
    with pytest.raises(ValueError, match="native_pipeline_not_enabled"):
        runtime.load_script()
    assert calls == []
    runtime.args.legacy_research = True
    runtime.load_script()
    assert calls == ["create", "on", "load", "prepare"]


def test_host_rejects_stale_deployment_before_any_native_call(case, socket_state):
    runtime = pipeline(case, socket_state)
    result = asyncio.run(runtime.dispatch(host_request(runtime, expected_deployment="stale")))
    assert result == {"status": "rejected", "diagnostic_code": "sender_upgrade_requires_restart"}
    assert runtime.calls == []


def test_pipeline_claim_sequence_payload_and_durable_ack_survive_restart(case, socket_state):
    first = pipeline(case, socket_state)
    def arm(intent):
        record = first.journal.record(intent["operation_id"], account_id=ACCOUNT)
        assert record["state"] == "dispatching"
        assert intent == {"recipient": "alice_fixture", "text": "Fixture message",
                          "operation_id": "fixture-operation", "dispatch_sequence": record["sequence"], "ttl_seconds": 60}
        return {"armed": True}
    first.script.exports_sync.arm = arm
    assert asyncio.run(first.dispatch(host_request(first))) == completion()
    assert not first.pending_operations
    restarted = pipeline(case, socket_state)
    repeated = asyncio.run(restarted.dispatch(host_request(restarted)))
    assert repeated["local_id"] == 7 and repeated["replayed"] is True
    assert restarted.calls == []
    asyncio.run(restarted.dispatch(host_request(restarted, operation_id="new-operation")))
    assert restarted.calls[1][-1] > first.calls[0][-1]


def test_arm_exception_is_durable_rejection_without_dispatch(case, socket_state):
    runtime = pipeline(case, socket_state)
    def fail_arm(_):
        raise ValueError("fixture account changed before dispatch")
    runtime.script.exports_sync.arm = fail_arm
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result == {"status": "rejected", "diagnostic_code": "native_arm_rejected"}
    record = runtime.journal.record("fixture-operation", account_id=ACCOUNT)
    assert record["state"] == "rejected"
    assert asyncio.run(runtime.dispatch(host_request(runtime)))["replayed"] is True
    assert runtime.calls == [] and not runtime.pending_operations


@pytest.mark.parametrize("bad_sequence", [False, True])
def test_uncertain_dispatch_only_reconciles_exact_sequence_without_resend(case, socket_state, bad_sequence):
    runtime = pipeline(case, socket_state)
    def interrupted(*args):
        runtime.calls.append(("sendnative", *args))
        raise RuntimeError("Response lost after dispatch")
    runtime.script.exports_sync.sendnative = interrupted
    first = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert first["status"] == "outcome_unknown"
    sequence = runtime.journal.record("fixture-operation", account_id=ACCOUNT)["sequence"]
    runtime.script.exports_sync.getresult = lambda operation: native_pipeline_completion(
        operation_known=True, dispatch_sequence=sequence + int(bad_sequence))
    asyncio.run(runtime.refresh_pending_operations())
    stored = runtime.journal.record("fixture-operation", account_id=ACCOUNT)["result"]
    if bad_sequence:
        assert stored["status"] == "outcome_unknown"
        assert runtime.pending_operations == {"fixture-operation"}
        assert not any(c[0] == "ack" for c in runtime.calls)
    else:
        assert stored == completion() and not runtime.pending_operations
    asyncio.run(runtime.dispatch(host_request(runtime)))
    assert len([c for c in runtime.calls if c[0] == "sendnative"]) == 1


def test_lost_ack_can_be_retried_after_native_recent_cache_eviction(case, socket_state):
    runtime = pipeline(case, socket_state)
    exports = runtime.script.exports_sync
    ack = exports.acknowledge
    attempts = []
    def lost(operation, sequence):
        attempts.append(operation)
        if len(attempts) == 1:
            raise RuntimeError("Lost release response")
        return ack(operation, sequence)
    exports.acknowledge = lost
    asyncio.run(runtime.dispatch(host_request(runtime)))
    assert runtime.pending_operations == {"fixture-operation"}
    exports.getresult = lambda operation: {"operation_known": False, "completed": False}
    asyncio.run(runtime.refresh_pending_operations())
    assert not runtime.pending_operations and len(attempts) == 2
    assert runtime.journal.record("fixture-operation", account_id=ACCOUNT)["result"] == completion()
    assert len([c for c in runtime.calls if c[0] == "sendnative"]) == 1


def test_background_reconciliation_does_not_starve_later_results(case, socket_state):
    runtime = pipeline(case, socket_state)
    sequences = {}
    for i in range(16):
        operation = f"fixture-{i:02}"
        claim, _ = runtime.journal.claim(operation, fingerprint("recipient", str(i)), ACCOUNT, "recipient")
        runtime.journal.finish(claim, {"status": "outcome_unknown"})
        sequences[operation] = runtime.journal.record(operation, account_id=ACCOUNT)["sequence"]
        runtime.pending_operations.add(operation)
    runtime.script.exports_sync.getresult = lambda op: (
        native_pipeline_completion(operation_known=True, dispatch_sequence=sequences[op]) if int(op[-2:]) >= 8
        else {"operation_known": False, "completed": False})
    async def scenario():
        await runtime.refresh_pending_operations()
        await runtime.refresh_pending_operations()
    asyncio.run(scenario())
    assert runtime.pending_operations == {f"fixture-{i:02}" for i in range(8)}
    assert len([c for c in runtime.calls if c[0] == "ack"]) == 8
    assert not any(c[0] in {"arm", "sendnative"} for c in runtime.calls)


def test_missing_native_operation_is_observation_only(case, socket_state):
    runtime = pipeline(case, socket_state)
    result = asyncio.run(runtime.dispatch(host_request(runtime, method="get_operation")))
    assert result["operation_known"] is False
    assert runtime.journal.record("fixture-operation", account_id=ACCOUNT) is None
    assert runtime.calls == []


@pytest.mark.parametrize("busy_field", ["inflight_count", "native_pending_jobs", "deferred_cleanup_count"])
def test_stop_waits_for_native_jobs_and_cleanup_even_after_js_completion(case, socket_state, busy_field):
    runtime = pipeline(case, socket_state)
    runtime.script.exports_sync.status = lambda: {"inflight_count": 0, "native_pending_jobs": 0,
        "deferred_cleanup_count": 0, busy_field: 1}
    runtime.script.exports_sync.disarm = lambda: runtime.calls.append(("disarm",))
    result = asyncio.run(runtime.dispatch(host_request(runtime, method="stop")))
    assert result["waiting_for_native_completion"] is True
    assert runtime.stop_requested and not runtime.stop_event.is_set()
    assert runtime.calls == [("disarm",)]
    assert asyncio.run(runtime.dispatch(host_request(runtime)))["diagnostic_code"] == "native_stopping"


def test_startup_drains_native_jobs_without_relaunching(case, socket_state, monkeypatch):
    runtime = pipeline(case, socket_state)
    runtime.stop_requested = True
    runtime.attach = lambda: None
    runtime.identity = lambda: runtime.started_identity
    state = {"inflight_count": 0, "native_pending_jobs": 1, "deferred_cleanup_count": 1}
    runtime.script.exports_sync.status = lambda: dict(state)
    sleeps = []
    async def drain(_):
        sleeps.append(1)
        state.update(native_pending_jobs=0, deferred_cleanup_count=0)
    monkeypatch.setattr("wechat_sender.native_host.asyncio.sleep", drain)
    asyncio.run(runtime.startup())
    assert runtime.stop_event.is_set() and sleeps == [1]
    assert runtime.calls == []


@pytest.mark.parametrize("immediate", [False, True])
def test_completed_native_result_has_no_fixed_poll_delay(case, socket_state, monkeypatch, immediate):
    runtime = pipeline(case, socket_state)
    raw = native_pipeline_completion(operation_known=True, dispatch_sequence=1)
    runtime.script.exports_sync.getresult = lambda operation: raw
    async def forbidden(_):
        pytest.fail("An available completion should not sleep")
    monkeypatch.setattr("wechat_sender.native_host.asyncio.sleep", forbidden)
    first = raw if immediate else {"status": "submitted", "operation_known": True, "dispatch_sequence": 1}
    assert asyncio.run(runtime.wait_result("fixture", first, 1)) == completion()


def test_ledger_reconciliation_is_monotonic_and_rejects_conflicting_evidence(case):
    ledger = case[1]
    claim, _ = ledger.claim("fixture", fingerprint(ALICE, "Hello"), ACCOUNT, ALICE)
    assert ledger.reconcile(claim, {"status": "outcome_unknown"})["status"] == "outcome_unknown"
    assert ledger.reconcile(claim, completion()) == completion()
    assert ledger.reconcile(claim, {"status": "outcome_unknown"}) == completion()
    for incompatible in (completion(8), {"status": "rejected"}):
        with pytest.raises(SenderError, match="submission_evidence_conflict"):
            ledger.reconcile(claim, incompatible)
    reopened = Ledger(ledger.path)
    assert reopened.record("fixture", account_id=ACCOUNT)["result"] == completion()
    assert reopened.record("fixture", account_id="another-account") is None
    assert reopened.lookup("fixture", fingerprint(ALICE, "Hello"))["replayed"] is True


@pytest.mark.parametrize("cancel_original", [False, True])
def test_concurrent_status_cannot_break_or_downgrade_original_submission(case, cancel_original):
    _, ledger, backend, service = case
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        operation = None
        async def send(target, text, op):
            nonlocal operation
            operation = op
            backend.calls.append((target, text, op))
            entered.set()
            await release.wait()
            return {"status": "outcome_unknown", "diagnostic_code": "lost_response"}
        async def observe(op):
            assert op == operation
            return {"operation_known": True, "operation_id": op, "account_id": ACCOUNT, "result": completion()}
        backend.send_text, backend.get_operation = send, observe
        task = asyncio.create_task(service.send_text(ALICE, "Hello", "fixture"))
        await entered.wait()
        assert (await service.get_send_status("fixture"))["local_id"] == 7
        if cancel_original:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            release.set()
            result = await task
            assert result["local_id"] == 7 and result["replayed"] is False
        replay = await service.send_text(ALICE, "Hello", "fixture")
        assert replay["local_id"] == 7 and replay["replayed"] is True
        assert len(backend.calls) == 1
        assert ledger.record("fixture", account_id=ACCOUNT)["result"] == completion()
    asyncio.run(scenario())


@pytest.mark.parametrize("mismatch", ["operation", "account", "unknown"])
def test_public_reconciliation_ignores_uncorrelated_observations(case, mismatch):
    _, ledger, backend, service = case
    claim, _ = ledger.claim("fixture", fingerprint(ALICE, "Hello"), ACCOUNT, ALICE)
    ledger.finish(claim, {"status": "outcome_unknown"})
    async def observe(op):
        return {"operation_known": mismatch != "unknown", "operation_id": "wrong" if mismatch == "operation" else op,
                "account_id": "wrong" if mismatch == "account" else ACCOUNT, "result": completion()}
    backend.get_operation = observe
    assert asyncio.run(service.get_send_status("fixture"))["status"] == "outcome_unknown"
    assert ledger.record("fixture", account_id=ACCOUNT)["result"] == {"status": "outcome_unknown"}
    assert backend.calls == []


def test_account_switch_during_status_does_not_return_previous_account_outbox(case):
    archive, ledger, backend, service = case
    claim, _ = ledger.claim("fixture", fingerprint(ALICE, "Hello"), ACCOUNT, ALICE)
    ledger.finish(claim, {"status": "outcome_unknown"})
    async def observe(op):
        with sqlite3.connect(archive.path) as db:
            db.execute("UPDATE generations SET account_id='another-account' WHERE generation=2")
        return {"operation_known": True, "operation_id": op, "account_id": ACCOUNT, "result": completion()}
    backend.get_operation = observe
    with pytest.raises(SenderError, match="archive_account_changed"):
        asyncio.run(service.get_send_status("fixture"))
    assert ledger.record("fixture", account_id=ACCOUNT)["result"] == {"status": "outcome_unknown"}
    assert backend.calls == []


def test_native_evidence_is_not_released_until_that_evidence_is_durable(case, socket_state, monkeypatch):
    runtime = pipeline(case, socket_state)
    original_finish = runtime.journal.finish
    def unavailable(*args):
        raise SenderError("ledger_unavailable")
    monkeypatch.setattr(runtime.journal, "finish", unavailable)
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result["status"] == "outcome_unknown"
    assert not any(c[0] == "ack" for c in runtime.calls)
    monkeypatch.setattr(runtime.journal, "finish", original_finish)
    sequence = runtime.journal.record("fixture-operation", account_id=ACCOUNT)["sequence"]
    runtime.script.exports_sync.getresult = lambda operation: native_pipeline_completion(
        operation_known=True, dispatch_sequence=sequence + 1)
    asyncio.run(runtime.refresh_pending_operations())
    assert not any(c[0] == "ack" for c in runtime.calls)
    assert runtime.pending_operations == {"fixture-operation"}
    runtime.script.exports_sync.getresult = lambda operation: native_pipeline_completion(
        operation_known=True, dispatch_sequence=sequence)
    asyncio.run(runtime.refresh_pending_operations())
    assert runtime.journal.record("fixture-operation", account_id=ACCOUNT)["result"] == completion()
    assert not runtime.pending_operations
    assert len([c for c in runtime.calls if c[0] == "sendnative"]) == 1


def test_temporary_archive_failure_does_not_end_background_reconciliation(case, socket_state):
    runtime = pipeline(case, socket_state)
    exports = runtime.script.exports_sync
    ack = exports.acknowledge
    exports.acknowledge = lambda *args: {"acknowledged": False}
    asyncio.run(runtime.dispatch(host_request(runtime)))
    sequence = runtime.journal.record("fixture-operation", account_id=ACCOUNT)["sequence"]
    exports.getresult = lambda operation: native_pipeline_completion(operation_known=True, dispatch_sequence=sequence)
    def inaccessible():
        raise SenderError("archive_unavailable")
    runtime.bound_account = inaccessible
    asyncio.run(runtime.refresh_pending_operations())
    assert runtime.pending_operations == {"fixture-operation"}
    runtime.bound_account = lambda: True
    exports.acknowledge = ack
    asyncio.run(runtime.refresh_pending_operations())
    assert not runtime.pending_operations
    assert len([c for c in runtime.calls if c[0] == "sendnative"]) == 1
