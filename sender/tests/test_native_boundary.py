"""Real local Unix-socket I/O with fixture peers; never starts or sends through WeChat."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import plistlib
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

from wechat_sender.backend import RECIPIENT_POLICY, NativeBackend
from wechat_sender.backend_protocol import SenderError
from wechat_sender.compatibility import inspect_app, validate_profile
from wechat_sender.deployment import DEPLOYMENT_FINGERPRINT
from wechat_sender.native_host import NativeRuntime, handle_connection
from wechat_sender.server import SendService
from test_sender import ACCOUNT, ALICE, BOB, GROUP, add_contact, case  # Synthetic archive fixtures only.


@pytest.fixture
def socket_state():
    # macOS Unix socket paths are short; pytest's default temp paths may exceed them.
    with tempfile.TemporaryDirectory(prefix="wx-mcp-", dir=Path("/tmp").resolve()) as name:
        yield Path(name)


def test_unavailable_endpoint_reports_false_without_creating_anything(socket_state, tmp_path):
    backend = NativeBackend(reader_archive=tmp_path / "archive.sqlite3", state=socket_state)
    result = asyncio.run(backend.status())
    assert result == {"ready": False, "identity_verified": False, "account_id": None,
                      "diagnostic_code": "native_runtime_unavailable"}
    assert list(socket_state.iterdir()) == []


def test_actual_private_socket_request_response_round_trip(socket_state, tmp_path):
    requests = []
    archive = tmp_path / "archive.sqlite3"
    async def scenario():
        async def peer(reader, writer):
            requests.append(json.loads(await reader.readline()))
            writer.write(json.dumps({"ready": False, "identity_verified": False, "account_id": None,
                                     "diagnostic_code": "native_probe_only"}).encode() + b"\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
        os.chmod(socket_state / "native.sock", 0o600)
        async with server:
            return await NativeBackend(reader_archive=archive, state=socket_state).status()
    result = asyncio.run(scenario())
    assert result["ready"] is False and result["diagnostic_code"] == "native_probe_only"
    assert requests == [{"method": "status", "reader_archive": str(archive.resolve())}]


def test_private_socket_preserves_native_local_evidence_without_promoting_status(socket_state, tmp_path):
    expected = {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
                "local_id": 7, "local_history_evidence": "native_send_result"}
    async def scenario():
        async def peer(reader, writer):
            request = json.loads(await reader.readline())
            assert request["method"] == "send_text"
            writer.write(json.dumps(expected).encode() + b"\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
        os.chmod(socket_state / "native.sock", 0o600)
        async with server:
            return await NativeBackend(reader_archive=tmp_path / "archive", state=socket_state).send_text(
                "fixture-recipient", "Fixture text", "fixture-operation")
    assert asyncio.run(scenario()) == expected


def test_configured_trial_socket_leaves_primary_endpoint_untouched(socket_state, tmp_path, monkeypatch):
    monkeypatch.setenv("WECHAT_SENDER_SOCKET", "native-trial.sock")
    async def scenario():
        async def peer(reader, writer):
            await reader.readline()
            writer.write(b'{"ready":false,"identity_verified":false,"account_id":null,"diagnostic_code":"trial_endpoint"}\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native-trial.sock"))
        os.chmod(socket_state / "native-trial.sock", 0o600)
        async with server:
            return await NativeBackend(reader_archive=tmp_path / "archive", state=socket_state).status()
    assert asyncio.run(scenario())["diagnostic_code"] == "trial_endpoint"
    assert not (socket_state / "native.sock").exists()
    with pytest.raises(SenderError, match="invalid_native_socket_name"):
        NativeBackend(reader_archive=tmp_path / "archive", state=socket_state, socket_name="../other.sock")


def test_unsafe_endpoint_directory_is_not_contacted(socket_state, tmp_path):
    connections = []
    async def scenario():
        async def peer(reader, writer):
            connections.append(True)
            writer.close()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
        os.chmod(socket_state, 0o755)
        try:
            async with server:
                return await NativeBackend(reader_archive=tmp_path / "archive", state=socket_state).status()
        finally:
            os.chmod(socket_state, 0o700)
    assert asyncio.run(scenario())["ready"] is False
    assert connections == []


def test_interrupted_socket_send_has_one_dispatch_and_no_reconnect_or_replay(socket_state, case):
    archive, ledger, _, _ = case
    requests = []
    async def scenario():
        async def peer(reader, writer):
            request = json.loads(await reader.readline())
            requests.append(request)
            if request["method"] == "status":
                writer.write(json.dumps({"ready": True, "identity_verified": True, "account_id": ACCOUNT,
                                         "diagnostic_code": None,
                                         "host": {"recipient_policy": RECIPIENT_POLICY, "native_pipeline": True,
                                                  "deployment_fingerprint": DEPLOYMENT_FINGERPRINT}}).encode() + b"\n")
                await writer.drain()
            # A send reaches this peer, then its response is lost. Do not guess rejection.
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
        os.chmod(socket_state / "native.sock", 0o600)
        async with server:
            backend = NativeBackend(reader_archive=archive.path, state=socket_state)
            service = SendService(archive, ledger, backend)
            first = await service.send_text(ALICE, "Fixture only", "socket-lost-reply")
            second = await service.send_text(ALICE, "Fixture only", "socket-lost-reply")
            return first, second
    first, second = asyncio.run(scenario())
    assert first["status"] == second["status"] == "outcome_unknown"
    assert first["operation_id"] == second["operation_id"]
    assert second["replayed"] is True
    assert [r["method"] for r in requests] == ["status", "send_text", "get_operation"]


def test_host_exception_after_send_dispatch_reports_unknown(socket_state, tmp_path):
    class RaisingRuntime:
        def __init__(self):
            self.calls = 0
        async def dispatch(self, request):
            self.calls += 1
            raise RuntimeError("failure after potentially invoking native code")
    runtime = RaisingRuntime()
    async def scenario():
        async def handle(reader, writer):
            await handle_connection(reader, writer, runtime)
        server = await asyncio.start_unix_server(handle, path=str(socket_state / "native.sock"))
        os.chmod(socket_state / "native.sock", 0o600)
        async with server:
            backend = NativeBackend(reader_archive=tmp_path / "archive", state=socket_state)
            return await backend.send_text("fixture-recipient", "fixture text", "one-operation")
    result = asyncio.run(scenario())
    assert result == {"status": "outcome_unknown", "diagnostic_code": "native_dispatch_interrupted"}
    assert runtime.calls == 1


def test_host_close_never_signals_a_process_with_changed_identity(monkeypatch):
    runtime = object.__new__(NativeRuntime)
    runtime.pid = 12345
    runtime.started_identity = "owned-original-start-time-and-executable"
    runtime.identity = lambda: "different-process"
    def forbidden(*args):
        pytest.fail("Must not signal an unowned/reused process")
    monkeypatch.setattr(os, "kill", forbidden)
    runtime.close()


def test_host_close_terminates_only_owned_identity_and_handles_exit_race(monkeypatch):
    runtime = object.__new__(NativeRuntime)
    runtime.pid = 12345
    runtime.started_identity = "owned"
    runtime.identity = lambda: "owned"
    signals = []
    def vanished(pid, sig):
        signals.append((pid, sig))
        raise ProcessLookupError
    monkeypatch.setattr(os, "kill", vanished)
    runtime.close()
    assert signals == [(12345, signal.SIGTERM)]


def mock_runtime(case, socket_state, *, prepared=True):
    """Fixture-only Frida exports: no process attachment, native code or network."""
    archive = case[0]
    (archive.path.parent / "config.json").write_text(json.dumps({"account_root": str(archive.path.parent / "fixture-account")}))
    args = SimpleNamespace(state=socket_state, reader_archive=archive.path,
                           prepared_sender=prepared, legacy_research=True,
                           enable_experimental_sending=True, attach_pid=12345,
                           expected_identity="fixture-owned-process")
    runtime = NativeRuntime(args, {})
    runtime.calls = []
    class Exports:
        def status(self):
            return {"ready": True, "sends_enabled": True, "inflight_count": 0}
        def arm(self, request):
            runtime.calls.append(("arm", request))
            return {"armed": True}
        def sendtext(self, task_id, proto, operation):
            runtime.calls.append(("send", task_id, proto, operation))
            return {"status": "submitted", "task_id": 123}
        def getresult(self, operation):
            runtime.calls.append(("result", operation))
            return {"status": "submitted", "completed": True, "task_id": 123,
                    "diagnostic_code": "server_response_received"}
    runtime.script = SimpleNamespace(exports_sync=Exports())
    async def status():
        return {"ready": True, "identity_verified": True, "account_id": ACCOUNT}
    runtime.status = status
    runtime.bound_account = lambda: True
    return runtime


def host_request(runtime, **changes):
    return {"method": "send_text", "reader_archive": str(runtime.args.reader_archive.resolve()),
            "target_username": "alice_fixture", "text": "Fixture message", "operation_id": "fixture-operation", **changes}


def test_native_submission_survives_restart_without_repeating_dispatch(case, socket_state):
    first = mock_runtime(case, socket_state)
    result = asyncio.run(first.dispatch(host_request(first)))
    assert result == {"status": "submitted", "diagnostic_code": "server_response_received", "task_id": 123}
    assert [call[0] for call in first.calls] == ["arm", "send", "result"]
    assert first.calls[1][1] == 0  # The native constructor owns task-ID allocation.
    restarted = mock_runtime(case, socket_state)
    replay = asyncio.run(restarted.dispatch(host_request(restarted)))
    assert replay["status"] == "submitted" and replay["replayed"] is True
    assert replay["operation_id"] == "fixture-operation"
    assert restarted.calls == []
    changed = asyncio.run(restarted.dispatch(host_request(restarted, text="Changed fixture")))
    assert changed == {"status": "rejected", "diagnostic_code": "request_id_reused_with_different_payload"}
    assert restarted.calls == []
    assert b"Fixture message" not in (socket_state / "native-outbox.sqlite3").read_bytes()


def test_native_dispatch_interruption_is_durable_and_never_retried(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    def interrupted(*args):
        runtime.calls.append(("send",))
        raise RuntimeError("Native dispatch may have started")
    runtime.script.exports_sync.sendtext = interrupted
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result["status"] == "outcome_unknown"
    restarted = mock_runtime(case, socket_state)
    assert asyncio.run(restarted.dispatch(host_request(restarted)))["status"] == "outcome_unknown"
    assert restarted.calls == []


def test_host_unknown_recipient_is_blocked_before_arming(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    result = asyncio.run(runtime.dispatch(host_request(runtime, target_username="unknown_fixture")))
    assert result == {"status": "rejected", "diagnostic_code": "recipient_not_found"}
    assert runtime.calls == []


@pytest.mark.parametrize("target", ["alice_fixture", "bob_fixture", "group_fixture@chatroom", "contact_only_fixture"])
def test_native_host_all_archive_contacts_and_groups_work_without_configuration(case, socket_state, target):
    add_contact(case[0])
    runtime = mock_runtime(case, socket_state)
    before = (hashlib.sha256(case[0].path.read_bytes()).hexdigest(), case[0].path.stat().st_mtime_ns)
    result = asyncio.run(runtime.dispatch(host_request(runtime, target_username=target)))
    assert result["status"] == "submitted"
    assert [call[0] for call in runtime.calls] == ["arm", "send", "result"]
    assert runtime.calls[0][1]["recipient"] == target
    after = (hashlib.sha256(case[0].path.read_bytes()).hexdigest(), case[0].path.stat().st_mtime_ns)
    assert after == before


def test_host_rejects_duplicate_raw_recipient_before_native_arm(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    with sqlite3.connect(case[0].path) as db:
        record = {"conversation_id": "conversation_" + "f" * 64, "source_username": "alice_fixture",
                  "kind": "direct", "display_name": "Duplicate fixture"}
        db.execute("INSERT INTO conversations VALUES(2,?,?)", (record["conversation_id"], json.dumps(record)))
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result == {"status": "rejected", "diagnostic_code": "recipient_ambiguous"}
    assert runtime.calls == []


@pytest.mark.parametrize("when", ["before_resolution", "during_native_status"])
def test_host_archive_account_change_cannot_dispatch_even_when_native_status_claims_ready(case, socket_state, when):
    runtime = mock_runtime(case, socket_state)
    def change_account():
        with sqlite3.connect(case[0].path) as db:
            db.execute("UPDATE generations SET account_id='different-fixture-account' WHERE generation=2")
    if when == "before_resolution":
        change_account()
    else:
        async def status():
            change_account()
            return {"ready": True, "identity_verified": True, "account_id": ACCOUNT}
        runtime.status = status
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result == {"status": "rejected", "diagnostic_code": "archive_account_mismatch"}
    assert runtime.calls == []


def test_host_rejects_recipient_removed_during_status_verification(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    async def status():
        with sqlite3.connect(case[0].path) as db:
            db.execute("DELETE FROM conversations WHERE generation=2 AND record_id=?", (ALICE,))
        return {"ready": True, "identity_verified": True, "account_id": ACCOUNT}
    runtime.status = status
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result == {"status": "rejected", "diagnostic_code": "recipient_not_found"}
    assert runtime.calls == []


def test_host_status_requires_native_send_gate_even_when_preparation_succeeded(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    runtime.bound_account = lambda: True
    runtime.script.exports_sync.status = lambda: {"ready": True, "sends_enabled": False,
        "diagnostic_code": "experimental_sending_not_approved"}
    result = asyncio.run(NativeRuntime.status(runtime))
    assert result["ready"] is False and result["identity_verified"] is True
    assert result["diagnostic_code"] == "experimental_sending_not_approved"


@pytest.fixture
def script_load_case(case, socket_state, tmp_path, monkeypatch):
    """Fixture files and script API only: no Frida evaluation or native loading."""
    runtime = mock_runtime(case, socket_state)
    package = tmp_path / "synthetic-package"
    package.mkdir()
    for name in ("native_text.js", "native_prepared_sender.js", "native_pipeline_sender.js"):
        (package / name).write_text("// fixture-source:" + name)
    library = package / "native_pipeline.dylib"
    library.write_bytes(b"synthetic fixture bytes; never loaded")
    runtime.profile = {"native_pipeline": {"enabled": True,
        "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest()}}
    calls, sources = [], []
    script = SimpleNamespace(on=lambda *args: calls.append("on"), load=lambda: calls.append("load"),
                             exports_sync=SimpleNamespace(prepare=lambda: calls.append("prepare")))
    def create_script(source, *, name):
        calls.append("create")
        sources.append(source)
        assert name == "wechat-sender-native"
        return script
    runtime.session = SimpleNamespace(create_script=create_script)
    runtime.script = None
    monkeypatch.setattr("wechat_sender.native_host.__file__", str(package / "native_host.py"))
    return runtime, package, calls, sources


@pytest.mark.parametrize("prepared,enabled,selected", [
    (False, False, "native_text.js"), (False, True, "native_text.js"),
    (True, None, "native_prepared_sender.js"), (True, False, "native_prepared_sender.js"),
    (True, 1, "native_prepared_sender.js"), (True, "true", "native_prepared_sender.js"),
    (True, True, "native_pipeline_sender.js"),
])
def test_pipeline_script_requires_explicit_prepared_mode_and_literal_profile_opt_in(script_load_case, prepared, enabled, selected):
    runtime, package, calls, sources = script_load_case
    runtime.args.prepared_sender = prepared
    if enabled is None:
        runtime.profile = {}
    else:
        runtime.profile["native_pipeline"]["enabled"] = enabled
    runtime.load_script()
    assert sources[0].endswith("// fixture-source:" + selected)
    assert calls == ["create", "on", "load"] + (["prepare"] if prepared else [])
    assert ("const PIPELINE_LIBRARY_PATH" in sources[0]) is (selected == "native_pipeline_sender.js")
    if selected == "native_pipeline_sender.js":
        assert json.dumps(str((package / "native_pipeline.dylib").resolve())) in sources[0]


@pytest.mark.parametrize("fault", ["missing", "changed_bytes", "missing_hash", "wrong_hash", "symlink"])
def test_pipeline_library_must_match_profile_before_any_script_creation(script_load_case, fault):
    runtime, package, calls, sources = script_load_case
    library = package / "native_pipeline.dylib"
    if fault == "missing":
        library.unlink()
    elif fault == "changed_bytes":
        library.write_bytes(b"different fixture build")
    elif fault == "missing_hash":
        del runtime.profile["native_pipeline"]["library_sha256"]
    elif fault == "wrong_hash":
        runtime.profile["native_pipeline"]["library_sha256"] = "0" * 64
    else:
        alternate = package / "matching-bytes-but-symlink.dylib"
        library.rename(alternate)
        library.symlink_to(alternate)
    with pytest.raises(ValueError, match="native_pipeline_library_mismatch"):
        runtime.load_script()
    assert calls == [] and sources == [] and runtime.script is None


def test_compiled_library_hash_is_part_of_managed_profile_identity(script_load_case, tmp_path):
    from wechat_sender.supervisor import profile_identity
    runtime, package, _, _ = script_load_case
    profile_path = tmp_path / "fixture-profile.json"
    profile_path.write_text(json.dumps(runtime.profile))
    original_profile_hash = profile_identity(profile_path)
    library = package / "native_pipeline.dylib"
    library.write_bytes(b"a new synthetic compiled library")
    with pytest.raises(ValueError, match="native_pipeline_library_mismatch"):
        runtime.load_script()
    runtime.profile["native_pipeline"]["library_sha256"] = hashlib.sha256(library.read_bytes()).hexdigest()
    profile_path.write_text(json.dumps(runtime.profile))
    assert profile_identity(profile_path) != original_profile_hash
    runtime.load_script()


def test_packaged_pipeline_assets_match_disabled_profile_without_loading_them():
    import wechat_sender.native_host as native_host
    package = Path(native_host.__file__).parent
    for name in ("native_pipeline.cpp", "native_pipeline_sender.js", "native_pipeline.dylib"):
        assert (package / name).is_file()
    profile = json.loads((package / "profiles/wechat-4.1.15-270135-arm64.json").read_text())
    assert profile["native_pipeline"]["enabled"] is False
    assert profile["native_pipeline"]["library_sha256"] == hashlib.sha256((package / "native_pipeline.dylib").read_bytes()).hexdigest()


@pytest.mark.parametrize("prepared,enabled,expected_call", [
    (False, True, "send"), (True, False, "send"),
    (True, 1, "send"), (True, True, "sendnative"),
])
def test_dispatch_uses_same_opt_in_gate_as_script_selection(case, socket_state, prepared, enabled, expected_call):
    runtime = mock_runtime(case, socket_state, prepared=prepared)
    runtime.profile = {"native_pipeline": {"enabled": enabled}}
    def sendnative(target, text, operation, sequence):
        runtime.calls.append(("sendnative", target, text, operation))
        return native_pipeline_completion(operation_known=True, dispatch_sequence=sequence)
    runtime.script.exports_sync.sendnative = sendnative
    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result["status"] == "submitted"
    assert [call[0] for call in runtime.calls if call[0] in {"send", "sendnative"}] == [expected_call]


@pytest.mark.parametrize("incorrect", ["executable", "identity"])
def test_attach_rejects_unowned_process_before_any_frida_call(case, socket_state, monkeypatch, incorrect):
    runtime = mock_runtime(case, socket_state)
    expected = socket_state / "WeChat-Sender.app/Contents/MacOS/WeChat"
    monkeypatch.setattr("wechat_sender.native_host.command", lambda *args: str(expected if incorrect == "identity" else Path("/Applications/WeChat.app/Contents/MacOS/WeChat")).encode())
    runtime.identity = lambda: "wrong-identity" if incorrect == "identity" else runtime.args.expected_identity
    runtime.bound_account = lambda: pytest.fail("Unowned process must be rejected before account inspection")
    with pytest.raises(ValueError, match="attach_process_identity_mismatch"):
        runtime.verify_attach_target()


def test_prepared_owned_copy_resumes_before_any_preparation(case, socket_state, monkeypatch):
    runtime = mock_runtime(case, socket_state)
    runtime.script = None
    calls = []
    (socket_state / "WeChat-Sender.app").mkdir()
    monkeypatch.setattr("wechat_sender.native_host.running_clients", lambda: False)
    monkeypatch.setattr("wechat_sender.native_host.validate_profile", lambda *args: {})
    def command(args, timeout):
        if args[0] == "/bin/cp":
            Path(args[-1]).mkdir()
        return b""
    monkeypatch.setattr("wechat_sender.native_host.command", command)
    device = SimpleNamespace(spawn=lambda *args, **kwargs: calls.append("spawn") or 12345,
                             attach=lambda pid: calls.append("attach") or SimpleNamespace(),
                             resume=lambda pid: calls.append("resume"))
    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_local_device=lambda: device))
    runtime.identity = lambda: "owned"
    runtime.load_script = lambda: pytest.fail("Preparation must wait until the resumed process is logged in")
    runtime.launch()
    assert calls == ["spawn", "attach", "resume"]
    assert runtime.owns_process is True and runtime.startup_diagnostic == "waiting_for_wechat_login"


def test_preparation_waits_for_bound_account_and_never_retries_unsafe_failure(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    runtime.script = None
    calls = []
    runtime.bound_account = lambda: False
    runtime.load_script = lambda: pytest.fail("Must not prepare before account binding")
    asyncio.run(runtime.prepare_when_bound())
    assert runtime.startup_diagnostic == "waiting_for_wechat_login"
    runtime.bound_account = lambda: True
    def load():
        calls.append("load")
        runtime.script = SimpleNamespace(exports_sync=SimpleNamespace(status=lambda: {
            "phase": "blocked", "diagnostic_code": "native_task_defaults_mismatch", "can_detach": True}))
    runtime.load_script = load
    asyncio.run(runtime.prepare_when_bound())
    assert calls == ["load"] and runtime.startup_diagnostic is None


def test_failed_start_does_not_leave_a_reusable_host(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    runtime.args.attach_pid = None
    def refuse():
        raise ValueError("close_wechat_before_test")
    runtime.launch = refuse
    asyncio.run(runtime.startup())
    assert runtime.stop_event.is_set()
    assert runtime.startup_diagnostic == "close_wechat_before_test"


def test_failed_identity_after_spawn_retains_cleanup_ownership(case, socket_state, monkeypatch):
    runtime = mock_runtime(case, socket_state)
    runtime.script = None
    (socket_state / "WeChat-Sender.app").mkdir()
    monkeypatch.setattr("wechat_sender.native_host.running_clients", lambda: False)
    monkeypatch.setattr("wechat_sender.native_host.validate_profile", lambda *args: {})
    def command(args, timeout):
        if args[0] == "/bin/cp":
            Path(args[-1]).mkdir()
        return b""
    monkeypatch.setattr("wechat_sender.native_host.command", command)
    device = SimpleNamespace(spawn=lambda *a, **k: 12345,
                             attach=lambda pid: pytest.fail("Identity failure occurs before attachment"))
    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_local_device=lambda: device))
    def failed_identity():
        raise subprocess.TimeoutExpired("fixture-ps", 5)
    runtime.identity = failed_identity
    with pytest.raises(subprocess.TimeoutExpired):
        runtime.launch()
    assert runtime.owns_process is True and runtime.pid == 12345
    assert runtime.started_identity is None and runtime.spawn_resumed is False


@pytest.mark.parametrize("same_executable", [True, False])
def test_unresumed_owned_spawn_cleanup_checks_exact_executable(case, socket_state, monkeypatch, same_executable):
    runtime = mock_runtime(case, socket_state)
    runtime.pid = 12345
    runtime.owns_process = True
    runtime.started_identity = None
    runtime.spawn_resumed = False
    calls = []
    runtime.device = SimpleNamespace(resume=lambda pid: calls.append(("resume", pid)))
    executable = socket_state / "WeChat-Sender.app/Contents/MacOS/WeChat"
    if not same_executable:
        executable = Path("/Applications/WeChat.app/Contents/MacOS/WeChat")
    inspections = 0
    def command(args, timeout):
        nonlocal inspections
        inspections += 1
        if inspections > 1:
            raise subprocess.CalledProcessError(1, "fixture-ps")
        return str(executable).encode()
    monkeypatch.setattr("wechat_sender.native_host.command", command)
    monkeypatch.setattr(os, "kill", lambda pid, sig: calls.append(("signal", sig)))
    monkeypatch.setattr("wechat_sender.native_host.time.sleep", lambda value: None)
    runtime.close()
    assert calls == ([("resume", 12345), ("signal", signal.SIGCONT), ("signal", signal.SIGTERM)] if same_executable else [])


def test_stop_request_disarms_and_blocks_later_sends(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    runtime.owns_process = True
    runtime.script.exports_sync.disarm = lambda: runtime.calls.append(("disarm",))
    stopped = asyncio.run(runtime.dispatch(host_request(runtime, method="stop")))
    assert stopped == {"status": "stopping", "waiting_for_app_exit": False, "waiting_for_native_completion": False}
    assert runtime.stop_event.is_set()
    assert asyncio.run(runtime.dispatch(host_request(runtime)))["diagnostic_code"] == "native_stopping"
    assert runtime.calls == [("disarm",)]


def test_host_replacement_with_different_configuration_rejects_before_dispatch(case, socket_state):
    runtime = mock_runtime(case, socket_state)
    result = asyncio.run(runtime.dispatch(host_request(runtime, expected_profile="changed-profile",
                                                       expected_recipient_policy=RECIPIENT_POLICY)))
    assert result == {"status": "rejected", "diagnostic_code": "running_host_configuration_mismatch"}
    assert runtime.calls == []


def test_attach_close_waits_for_owned_tasks_and_never_signals_existing_client(monkeypatch):
    calls = []
    states = iter([{"can_detach": False}, {"can_detach": True}])
    runtime = object.__new__(NativeRuntime)
    runtime.owns_process = False
    runtime.started_identity = "owned"
    runtime.identity = lambda: "owned"
    runtime.args = SimpleNamespace(prepared_sender=True)
    def status():
        calls.append("status")
        return next(states)
    runtime.script = SimpleNamespace(exports_sync=SimpleNamespace(status=status, disarm=lambda: calls.append("disarm")),
                                     unload=lambda: calls.append("unload"))
    runtime.session = SimpleNamespace(detach=lambda: calls.append("detach"))
    monkeypatch.setattr(os, "kill", lambda *args: pytest.fail("An attached client must never be terminated"))
    monkeypatch.setattr("wechat_sender.native_host.time.sleep", lambda duration: calls.append("wait"))
    runtime.close()
    assert calls == ["disarm", "status", "wait", "status", "unload", "detach"]


@pytest.mark.parametrize("raw,expected", [
    ({"status": "submitted", "completed": True, "diagnostic_code": "server_response_received"},
     {"status": "submitted", "diagnostic_code": "server_response_received"}),
    ({"status": "acknowledged", "server_ret_present": True, "server_ret": 0},
     {"status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}),
    ({"status": "acknowledged", "server_ret_present": True, "server_ret": False,
      "message_ret_present": True, "message_ret": 0, "message_correlated": True},
     {"status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}),
    ({"status": "failed", "server_ret_present": True, "server_ret": 0,
      "message_ret_present": True, "message_ret": -1, "message_correlated": True},
     {"status": "rejected", "diagnostic_code": "server_rejected"})])
def test_response_evidence_does_not_promote_global_success_to_delivery(raw, expected):
    assert NativeRuntime.submission_result(raw) == expected


def native_pipeline_completion(**changes):
    """Synthetic completion contract, not evidence of a real native send."""
    return {"status": "native_pipeline_completed", "completed": True,
            "native_status": 0, "native_error": 0, "local_id": 1234,
            "recipient_correlated": True, "request_correlated": True, **changes}


@pytest.mark.parametrize("local_id", [1, 2**32 - 1])
def test_native_pipeline_result_is_submission_without_server_or_delivery_claim(local_id):
    raw = native_pipeline_completion(local_id=local_id, server_id="987654321",
                                     diagnostic_code="server_acknowledged")
    assert NativeRuntime.submission_result(raw) == {
        "status": "submitted", "diagnostic_code": "native_pipeline_completed",
        "local_id": local_id, "local_history_evidence": "native_send_result"}


@pytest.mark.parametrize("field", ["completed", "native_status", "native_error", "local_id",
                                   "recipient_correlated", "request_correlated"])
def test_native_pipeline_completion_requires_every_evidence_field(field):
    raw = native_pipeline_completion()
    del raw[field]
    assert NativeRuntime.submission_result(raw) == {
        "status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}


@pytest.mark.parametrize("change", [
    {"completed": 1}, {"completed": False},
    {"native_status": False}, {"native_status": 1}, {"native_status": "0"},
    {"native_error": False}, {"native_error": -1}, {"native_error": 0.0},
    {"local_id": True}, {"local_id": 0}, {"local_id": -1},
    {"local_id": 2**32}, {"local_id": "1234"},
    {"recipient_correlated": 1}, {"recipient_correlated": False},
    {"request_correlated": 1}, {"request_correlated": False},
])
def test_native_pipeline_malformed_evidence_remains_unknown(change):
    assert NativeRuntime.submission_result(native_pipeline_completion(**change)) == {
        "status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}


@pytest.mark.parametrize("immediate", [False, True])
def test_native_pipeline_completion_polls_once_or_returns_immediately_and_never_resends(case, socket_state, immediate):
    runtime = mock_runtime(case, socket_state)
    def sendtext(task_id, proto, operation):
        runtime.calls.append(("send", operation))
        return native_pipeline_completion() if immediate else {"status": "submitted"}
    def getresult(operation):
        runtime.calls.append(("result", operation))
        return native_pipeline_completion()
    runtime.script.exports_sync.sendtext = sendtext
    runtime.script.exports_sync.getresult = getresult

    result = asyncio.run(runtime.dispatch(host_request(runtime)))
    assert result == {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
                      "local_id": 1234, "local_history_evidence": "native_send_result"}
    assert [call[0] for call in runtime.calls] == (["arm", "send"] if immediate else ["arm", "send", "result"])

    restarted = mock_runtime(case, socket_state)
    replay = asyncio.run(restarted.dispatch(host_request(restarted)))
    assert replay == result | {"operation_id": "fixture-operation", "replayed": True}
    assert restarted.calls == []


def fixture_app(tmp_path):
    """A synthetic Mach-O container; no executable app code is loaded or run."""
    app = tmp_path / "Fixture.app"
    resources = app / "Contents/Resources"
    resources.mkdir(parents=True)
    with (app / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump({"CFBundleShortVersionString": "fixture-version", "CFBundleVersion": "fixture-build"}, stream)
    offset, code = 0x200, bytes(range(128))
    segment = struct.pack("<II16sQQQQIIII", 0x19, 152, b"__TEXT", 0, 0x1000, 0, offset + len(code), 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", offset, len(code), offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 6, 1, 152, 0, 0)
    image = (header + segment + section).ljust(offset, b"\0") + code
    (resources / "wechat.dylib").write_bytes(image)
    names = ["taskCtor", "taskDtor", "startTask", "req2buf", "buf2resp", "onTaskEnd", "autoBufferWrite", "stringAssign"]
    profile = inspect_app(app) | {
        "offsets": {name: hex(offset + index * 16) for index, name in enumerate(names)},
        "expected_bytes": {name: code[index * 16:(index + 1) * 16].hex() for index, name in enumerate(names)}}
    return app, profile


@pytest.mark.parametrize("change,error", [("code_hash", "profile_fingerprint_mismatch"),
                                         ("version", "profile_fingerprint_mismatch"),
                                         ("instruction", "profile_signature_mismatch"),
                                         ("outside_code", "profile_address_outside_code")])
def test_compatibility_rejects_inexact_profiles(tmp_path, change, error):
    app, profile = fixture_app(tmp_path)
    assert validate_profile(app, profile) == inspect_app(app)
    if change == "code_hash":
        profile["code_sha256"] = "0" * 64
    elif change == "version":
        profile["version"] = "different-version"
    elif change == "instruction":
        profile["expected_bytes"]["taskCtor"] = "ff" * 16
    else:
        profile["offsets"]["taskCtor"] = "0x100"
    with pytest.raises(ValueError, match=error):
        validate_profile(app, profile)
