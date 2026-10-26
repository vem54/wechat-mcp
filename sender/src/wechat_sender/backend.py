"""Private Unix-socket client for the native, non-UI runtime.

No runtime is started by this client. An absent or unverified runtime is an
unavailable sender, never a simulated success. Connections are never retried.
"""
import asyncio
import json
import os
import re
from pathlib import Path
import stat

from .backend_protocol import SenderError
from .deployment import DEPLOYMENT_FINGERPRINT

DEFAULT_STATE = Path.home() / "Library/Application Support/WechatSender"
MAX_FRAME = 131072
RECIPIENT_POLICY = "active_archive_contacts_v1"


def socket_filename(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}\.sock", value):
        raise SenderError("invalid_native_socket_name")
    return value


def sender_state() -> Path:
    return Path(os.environ.get("WECHAT_SENDER_STATE", str(DEFAULT_STATE)))


class NativeBackend:
    def __init__(self, *, reader_archive: Path, state: Path | None = None, socket_name: str | None = None,
                 expected_profile: str | None = None):
        self.reader_archive = reader_archive.resolve()
        self.state = state or sender_state()
        self.socket_name = socket_filename(socket_name or os.environ.get("WECHAT_SENDER_SOCKET", "native.sock"))
        self.expected_profile = expected_profile
        self.expected_deployment = DEPLOYMENT_FINGERPRINT

    async def _request(self, request: dict) -> dict:
        # Parent permissions protect both the local endpoint and the session.
        directory = self.state.lstat()
        sock = self.state / self.socket_name
        inode = sock.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                or directory.st_mode & 0o077 or not stat.S_ISSOCK(inode.st_mode)
                or inode.st_uid != os.getuid()):
            raise SenderError("unsafe_native_endpoint")
        reader, writer = await asyncio.open_unix_connection(str(sock), limit=MAX_FRAME)
        try:
            request["reader_archive"] = str(self.reader_archive)
            if request.get("method") not in {"status", "stop"}:
                request["expected_deployment"] = self.expected_deployment
            if self.expected_profile is not None:
                request["expected_profile"] = self.expected_profile
                request["expected_recipient_policy"] = RECIPIENT_POLICY
            writer.write(json.dumps(request, ensure_ascii=False).encode() + b"\n")
            await writer.drain()
            response = await reader.readline()
            if not response.endswith(b"\n") or len(response) >= MAX_FRAME:
                raise SenderError("invalid_native_response")
            result = json.loads(response)
            if not isinstance(result, dict):
                raise SenderError("invalid_native_response")
            return result
        finally:
            writer.close()
            await writer.wait_closed()

    async def status(self) -> dict:
        try:
            result = await asyncio.wait_for(self._request({"method": "status"}), 5)
            if not {"ready", "identity_verified", "account_id"} <= result.keys():
                raise SenderError("invalid_native_response")
            host = result.get("host", {})
            if isinstance(host, dict) and host.get("managed") is True and host.get("deployment_fingerprint") != self.expected_deployment:
                return result | {"ready": False, "identity_verified": False, "account_id": None,
                                 "diagnostic_code": "sender_upgrade_requires_restart"}
            if result.get("ready") is True and isinstance(host, dict) and host.get("native_pipeline") is not True:
                return result | {"ready": False, "identity_verified": False, "account_id": None,
                                 "diagnostic_code": "native_pipeline_not_enabled"}
            if result.get("ready") is True and (not isinstance(host, dict)
                                                or host.get("recipient_policy") != RECIPIENT_POLICY):
                # Preserve lifecycle metadata so the supervisor can stop a
                # legacy host, but no new MCP client may send through it.
                return result | {"ready": False, "identity_verified": False, "account_id": None,
                                 "diagnostic_code": "running_host_configuration_mismatch"}
            if self.expected_profile is not None:
                if (not isinstance(host, dict) or host.get("managed") is not True
                        or host.get("prepared_sender") is not True or host.get("stopping") is not False
                        or host.get("profile_sha256") != self.expected_profile
                        or host.get("recipient_policy") != RECIPIENT_POLICY):
                    return {"ready": False, "identity_verified": False, "account_id": None,
                            "diagnostic_code": "running_host_configuration_mismatch"}
            return result
        except (OSError, ValueError, SenderError, asyncio.TimeoutError):
            return {"ready": False, "identity_verified": False, "account_id": None,
                    "diagnostic_code": "native_runtime_unavailable"}

    async def send_text(self, target_username: str, text: str, operation_id: str) -> dict:
        # The service has already persisted dispatching. Any failure after this
        # point is uncertain; never reconnect and repeat a send.
        try:
            result = await asyncio.wait_for(self._request({"method": "send_text",
                "target_username": target_username, "text": text,
                "operation_id": operation_id}), 15)
            if result.get("status") not in {"submitted", "rejected", "outcome_unknown"}:
                raise SenderError("invalid_native_response")
            return result
        except (OSError, ValueError, SenderError, asyncio.TimeoutError):
            return {"status": "outcome_unknown", "diagnostic_code": "native_outcome_unknown"}

    async def get_operation(self, operation_id: str) -> dict:
        """Observe one durable intent. This method cannot arm or submit a send."""
        try:
            return await asyncio.wait_for(self._request({"method": "get_operation", "operation_id": operation_id}), 5)
        except (OSError, ValueError, SenderError, asyncio.TimeoutError):
            return {"operation_known": False, "diagnostic_code": "native_operation_status_unavailable"}


def create_backend(*, reader_archive: Path) -> NativeBackend:
    return NativeBackend(reader_archive=reader_archive)
