"""Explicit lifecycle control for one local native host; never retries a send.

The generated MCP configuration opts in to starting a host at process startup.
Status/tool calls themselves do not launch apps. No client configuration is edited.
"""
import argparse
import asyncio
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .backend import DEFAULT_STATE, RECIPIENT_POLICY, NativeBackend, socket_filename
from .backend_protocol import SenderError
from .native_host import DEFAULT_ARCHIVE, private_dir
from .deployment import DEPLOYMENT_FINGERPRINT


def profile_identity(profile: Path) -> str:
    value = json.loads(profile.read_text())
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def compatible_host(status: dict, profile_hash: str) -> bool:
    host = status.get("host", {})
    return (host.get("managed") is True and host.get("prepared_sender") is True
            and host.get("profile_sha256") == profile_hash
            and host.get("deployment_fingerprint") == DEPLOYMENT_FINGERPRINT
            and host.get("recipient_policy") == RECIPIENT_POLICY and host.get("stopping") is False)


async def ensure_started(*, state: Path, reader_archive: Path, profile: Path,
                         socket_name: str = "native.sock",
                         startup_timeout: float = 12) -> dict:
    """Start one host if absent. A running but not-ready host is never restarted."""
    state = state.expanduser().absolute()
    reader_archive = reader_archive.expanduser().resolve()
    profile = profile.expanduser().resolve()
    socket_filename(socket_name)
    profile_data = json.loads(profile.read_text())
    if profile_data.get("native_pipeline", {}).get("enabled") is not True:
        raise SenderError("native_pipeline_not_enabled")
    profile_hash = profile_identity(profile)
    private_dir(state)
    backend = NativeBackend(reader_archive=reader_archive, state=state, socket_name=socket_name)
    with (state / "supervisor.lock").open("a") as lock:
        os.chmod(state / "supervisor.lock", 0o600)
        # Multiple MCP clients may start concurrently. Serialize only startup;
        # the host also holds an exclusive prepared-host lock for its lifetime.
        await asyncio.to_thread(fcntl.flock, lock.fileno(), fcntl.LOCK_EX)
        try:
            current = await backend.status()
            if current.get("host", {}).get("managed") is True:
                if current["host"].get("deployment_fingerprint") != DEPLOYMENT_FINGERPRINT:
                    raise SenderError("sender_upgrade_requires_restart")
                if not compatible_host(current, profile_hash):
                    raise SenderError("running_host_configuration_mismatch")
                return current
            if current.get("diagnostic_code") != "native_runtime_unavailable":
                raise SenderError("existing_endpoint_is_not_managed_sender")
            argv = [sys.executable, "-m", "wechat_sender.native_host", "run",
                    "--state", str(state), "--reader-archive", str(reader_archive),
                    "--profile", str(profile), "--prepared-sender", "--socket-name", socket_name,
                    "--enable-experimental-sending"]
            log_path = state / "native-host.log"
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "ab", buffering=0) as log:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + startup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise SenderError("native_host_start_failed")
                current = await backend.status()
                if compatible_host(current, profile_hash):
                    return current
                await asyncio.sleep(.1)
            # Do not kill or repeat an uncertain launch. A subsequent start
            # observes the same endpoint/lock, never retries a message.
            raise SenderError("native_host_start_pending")
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


async def stop_host(*, state: Path, reader_archive: Path, socket_name: str = "native.sock") -> dict:
    backend = NativeBackend(reader_archive=reader_archive, state=state, socket_name=socket_name)
    current = await backend.status()
    if current.get("host", {}).get("managed") is not True:
        return {"status": "not_running"} if current.get("diagnostic_code") == "native_runtime_unavailable" else {
            "status": "rejected", "diagnostic_code": "existing_endpoint_is_not_managed_sender"}
    try:
        return await asyncio.wait_for(backend._request({"method": "stop"}), 20)
    except (OSError, ValueError, SenderError, TimeoutError):
        return {"status": "outcome_unknown", "diagnostic_code": "native_stop_response_unavailable"}


def client_config(*, state: Path, reader_archive: Path, profile: Path,
                  socket_name: str = "native.sock") -> dict:
    """A reviewable fragment only; does not read or overwrite client settings."""
    socket_filename(socket_name)
    args = ["-m", "wechat_sender.server", "--reader-state-dir", str(reader_archive.expanduser().resolve().parent),
            "--sender-state-dir", str(state.expanduser().absolute()), "--ensure-native-host",
            "--native-profile", str(profile.expanduser().resolve()), "--native-socket-name", socket_name]
    return {"mcpServers": {"wechat_sender": {"command": sys.executable, "args": args}}}


def public_status(result: dict) -> dict:
    """CLI diagnostics omit the internal account binding and recipient identities."""
    public = {key: result[key] for key in ("ready", "identity_verified", "diagnostic_code", "status",
                                          "waiting_for_app_exit", "waiting_for_native_completion", "error") if key in result}
    if isinstance(result.get("host"), dict):
        public["host"] = {key: result["host"][key] for key in ("managed", "owns_app", "stopping", "prepared_sender", "recipient_policy")
                          if key in result["host"]}
    if isinstance(result.get("probe"), dict):
        public["native"] = {key: result["probe"][key] for key in ("phase", "inflight_count", "lifetime_policy",
                           "operation_capacity_remaining", "operation_lifetime_limit", "native_pending_jobs",
                           "native_retained_jobs", "deferred_cleanup_count", "completion_policy", "outgoing_local_history_reconciled")
                            if key in result["probe"]}
    return public


def main():
    parser = argparse.ArgumentParser(description="Explicit start/stop/status/config for the local WeChat sender")
    parser.add_argument("action", choices=["start", "stop", "status", "config"])
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--reader-archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--socket-name", default="native.sock")
    # Older saved client commands still start; this option no longer sets policy.
    parser.add_argument("--allow-recipient", dest="obsolete_allow_recipient", action="append", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.obsolete_allow_recipient:
        print("Obsolete --allow-recipient ignored; all active archive recipients are available.", file=sys.stderr)
    if args.action in {"start", "config"} and args.profile is None:
        parser.error("--profile is required for start/config")
    values = {"state": args.state, "reader_archive": args.reader_archive, "socket_name": args.socket_name}
    try:
        if args.action == "start":
            result = asyncio.run(ensure_started(**values, profile=args.profile))
        elif args.action == "stop":
            result = asyncio.run(stop_host(**values))
        elif args.action == "status":
            result = asyncio.run(NativeBackend(**values).status())
        else:
            result = client_config(**values, profile=args.profile)
    except (SenderError, OSError, ValueError) as error:
        result = {"error": error.code if isinstance(error, SenderError) else "sender_configuration_invalid"}
    print(json.dumps(result if args.action == "config" else public_status(result), indent=2))
    if "error" in result:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
