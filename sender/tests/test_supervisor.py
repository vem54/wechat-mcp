"""Lifecycle tests use fixture sockets and mocked Popen; no WeChat process is run."""
import asyncio
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from wechat_sender.backend import RECIPIENT_POLICY, NativeBackend
from wechat_sender.backend_protocol import SenderError
from wechat_sender.deployment import DEPLOYMENT_FINGERPRINT
from wechat_sender.supervisor import client_config, ensure_started, profile_identity, public_status, stop_host
from test_native_boundary import socket_state
from test_sender import case


@pytest.fixture
def fixture_profile(tmp_path):
    path = tmp_path / "fixture-profile.json"
    path.write_text('{"fixture":true,"native_pipeline":{"enabled":true}}')
    return path


def state_response(profile):
    return {"ready": False, "identity_verified": False, "account_id": None,
            "diagnostic_code": "waiting_for_wechat_login",
            "host": {"managed": True, "prepared_sender": True, "stopping": False,
                     "owns_app": True, "profile_sha256": profile_identity(profile),
                     "deployment_fingerprint": DEPLOYMENT_FINGERPRINT, "native_pipeline": True,
                     "recipient_policy": RECIPIENT_POLICY}}


async def fixture_socket(socket_state, response, requests):
    async def peer(reader, writer):
        requests.append(json.loads(await reader.readline()))
        writer.write(json.dumps(response).encode() + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
    os.chmod(socket_state / "native.sock", 0o600)
    return server


def test_existing_not_ready_host_is_reused_without_launch_or_restart(socket_state, fixture_profile, monkeypatch):
    monkeypatch.setattr("wechat_sender.supervisor.subprocess.Popen", lambda *a, **k: pytest.fail("Must reuse existing host while login is pending"))
    requests = []
    async def scenario():
        response = state_response(fixture_profile)
        server = await fixture_socket(socket_state, response, requests)
        async with server:
            return await ensure_started(state=socket_state, reader_archive=socket_state / "fixture-archive",
                                        profile=fixture_profile)
    assert asyncio.run(scenario())["diagnostic_code"] == "waiting_for_wechat_login"
    assert [r["method"] for r in requests] == ["status"]


def test_legacy_host_requires_controlled_restart_without_second_injection(socket_state, fixture_profile, monkeypatch):
    monkeypatch.setattr("wechat_sender.supervisor.subprocess.Popen", lambda *a, **k: pytest.fail("Do not start another host to change policy"))
    async def scenario():
        legacy = state_response(fixture_profile)
        del legacy["host"]["recipient_policy"]
        legacy["host"]["allowed_recipients"] = ["filehelper"]
        server = await fixture_socket(socket_state, legacy, [])
        async with server:
            with pytest.raises(SenderError, match="running_host_configuration_mismatch"):
                await ensure_started(state=socket_state, reader_archive=socket_state / "fixture-archive",
                                     profile=fixture_profile)
    asyncio.run(scenario())


def test_start_uses_current_python_one_host_without_recipient_configuration(socket_state, fixture_profile, monkeypatch):
    calls, servers = [], []
    async def scenario():
        async def start_fixture():
            servers.append(await fixture_socket(socket_state, state_response(fixture_profile), []))
        def fake_popen(argv, **kwargs):
            calls.append((argv, kwargs))
            asyncio.create_task(start_fixture())
            return SimpleNamespace(poll=lambda: None)
        monkeypatch.setattr("wechat_sender.supervisor.subprocess.Popen", fake_popen)
        try:
            result = await ensure_started(state=socket_state, reader_archive=socket_state / "fixture-archive",
                                          profile=fixture_profile)
            assert result["host"]["managed"] is True
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
    asyncio.run(scenario())
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[:4] == [sys.executable, "-m", "wechat_sender.native_host", "run"]
    assert "--allow-recipient" not in argv and "filehelper" not in argv
    assert "--prepared-sender" in argv and "--attach-pid" not in argv
    assert kwargs["start_new_session"] is True


def test_stop_uses_private_endpoint_and_never_signals_an_arbitrary_pid(socket_state, fixture_profile, monkeypatch):
    monkeypatch.setattr(os, "kill", lambda *a: pytest.fail("Supervisor stop must use host ownership checks"))
    calls = []
    async def scenario():
        response = state_response(fixture_profile)
        async def peer(reader, writer):
            request = json.loads(await reader.readline())
            calls.append(request["method"])
            result = response if request["method"] == "status" else {"status": "stopping", "waiting_for_app_exit": False}
            writer.write(json.dumps(result).encode() + b"\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(peer, path=str(socket_state / "native.sock"))
        os.chmod(socket_state / "native.sock", 0o600)
        async with server:
            return await stop_host(state=socket_state, reader_archive=socket_state / "fixture-archive")
    assert asyncio.run(scenario())["status"] == "stopping"
    assert calls == ["status", "stop"]


def test_generated_config_is_explicit_autostart_fragment_and_writes_no_files(socket_state, fixture_profile):
    before = set(socket_state.iterdir())
    result = client_config(state=socket_state, reader_archive=socket_state / "reader/archive.sqlite3",
                           profile=fixture_profile)
    entry = result["mcpServers"]["wechat_sender"]
    assert entry["command"] == sys.executable
    assert entry["args"][:2] == ["-m", "wechat_sender.server"]
    assert "--ensure-native-host" in entry["args"]
    assert "--allow-recipient" not in entry["args"] and "filehelper" not in entry["args"]
    assert set(socket_state.iterdir()) == before


def test_mcp_backend_cannot_use_different_host_after_supervisor_refuses_it(socket_state, fixture_profile):
    requests = []
    async def scenario():
        response = state_response(fixture_profile) | {"ready": True, "identity_verified": True, "account_id": "fixture"}
        server = await fixture_socket(socket_state, response, requests)
        async with server:
            backend = NativeBackend(state=socket_state, reader_archive=socket_state / "archive",
                                    expected_profile="another-profile")
            return await backend.status()
    result = asyncio.run(scenario())
    assert result["ready"] is False and result["diagnostic_code"] == "running_host_configuration_mismatch"
    assert requests[0]["expected_profile"] == "another-profile"
    assert requests[0]["expected_recipient_policy"] == RECIPIENT_POLICY
    assert "expected_recipients" not in requests[0]


def test_cli_status_omits_internal_account_and_recipient_binding(fixture_profile):
    value = state_response(fixture_profile)
    value["account_id"] = "private-account-uuid"
    value["host"]["allowed_recipients"] = ["private-username"]
    result = public_status(value)
    assert result["diagnostic_code"] == "waiting_for_wechat_login"
    assert "account_id" not in result
    assert "private" not in json.dumps(result)
    assert "profile_sha256" not in result["host"]


def test_manual_mcp_mode_rejects_legacy_host_readiness_but_retains_stop_metadata(socket_state, fixture_profile):
    async def scenario():
        legacy = state_response(fixture_profile) | {"ready": True, "identity_verified": True, "account_id": "fixture"}
        del legacy["host"]["recipient_policy"]
        legacy["host"]["allowed_recipients"] = ["filehelper"]
        requests = []
        server = await fixture_socket(socket_state, legacy, requests)
        async with server:
            status = await NativeBackend(state=socket_state, reader_archive=socket_state / "archive").status()
            assert status["ready"] is False and status["diagnostic_code"] == "running_host_configuration_mismatch"
            assert status["host"]["managed"] is True
            # A controller can still identify and ask this legacy host to stop.
            await stop_host(state=socket_state, reader_archive=socket_state / "archive")
        assert [request["method"] for request in requests] == ["status", "status", "stop"]
    asyncio.run(scenario())


def test_legacy_config_flags_are_ignored_and_not_regenerated(socket_state, fixture_profile, monkeypatch, capsys):
    from wechat_sender.supervisor import main
    monkeypatch.setattr(sys, "argv", ["wechat-sender-control", "config", "--state", str(socket_state),
        "--reader-archive", str(socket_state / "archive"), "--profile", str(fixture_profile),
        "--allow-recipient", "old-private-recipient"])
    main()
    output = capsys.readouterr()
    configured = json.loads(output.out)["mcpServers"]["wechat_sender"]["args"]
    assert "--allow-recipient" not in configured and "old-private-recipient" not in output.out + output.err
    assert "ignored" in output.err


def test_legacy_host_flags_parse_without_creating_a_policy(socket_state, fixture_profile, monkeypatch, capsys):
    import wechat_sender.native_host as native_host
    received = []
    async def no_runtime(args, profile):
        received.append(vars(args))
    monkeypatch.setattr(native_host, "run", no_runtime)
    monkeypatch.setattr(native_host.os, "umask", lambda value: None)
    monkeypatch.setattr(sys, "argv", ["wechat-native-host", "run", "--state", str(socket_state),
        "--profile", str(fixture_profile), "--allow-recipient", "old-private-recipient"])
    native_host.main()
    assert "allow_recipient" not in received[0]
    assert "ignored" in capsys.readouterr().err


def test_legacy_mcp_flags_do_not_restrict_new_service(case, monkeypatch, capsys):
    import wechat_sender.server as server_module
    archive, ledger, _, _ = case
    received = []
    def fake_server(service):
        received.append(service)
        return SimpleNamespace(run=lambda **kwargs: None)
    monkeypatch.setattr(server_module, "create_server", fake_server)
    monkeypatch.setenv("WECHAT_SENDER_STATE", "fixture-before")
    monkeypatch.setattr(sys, "argv", ["wechat-sender-mcp", "--reader-state-dir", str(archive.path.parent),
        "--sender-state-dir", str(ledger.path.parent), "--allow-recipient", "old-private-recipient"])
    server_module.main()
    assert len(received[0].list_recipients()["items"]) == 3
    assert not hasattr(received[0].backend, "expected_recipients")
    assert "ignored" in capsys.readouterr().err
