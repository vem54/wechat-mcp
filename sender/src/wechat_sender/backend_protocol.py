"""Contract for the real transport. This module never simulates successful sends."""
from typing import Protocol, TypedDict


class BackendStatus(TypedDict):
    # Both booleans must be literally True before any send can be dispatched.
    ready: bool
    identity_verified: bool
    # The archive account UUID must be independently bound to the native account.
    # It is not a WeChat username. Merely copying the archive UUID is not verification.
    account_id: str | None
    diagnostic_code: str | None


class SendResult(TypedDict, total=False):
    status: str
    diagnostic_code: str
    message_id: str
    server_id: str
    local_id: int
    # Native send pipeline returned this local ID. This is not independent
    # archive reconciliation, server acceptance, UI visibility, or delivery.
    local_history_evidence: str


def native_local_result_fields(raw: dict) -> dict:
    """Expose only the complete, narrowly defined native-result evidence pair."""
    if (raw.get("status") == "submitted"
            and raw.get("diagnostic_code") == "native_pipeline_completed"
            and type(raw.get("local_id")) is int and 0 < raw["local_id"] < 2**32
            and raw.get("local_history_evidence") == "native_send_result"):
        return {"local_id": raw["local_id"], "local_history_evidence": "native_send_result"}
    return {}


class SendBackend(Protocol):
    """An existing, verified transport; status() must not launch or log into WeChat.

    send_text may perform exactly one native submission. It must not retry an
    uncertain call. operation_id is a unique ledger ID, useful for correlation.
    Return only submitted, observed_in_local_history, delivery_confirmed,
    rejected, or outcome_unknown. A local API return is not delivery evidence.
    """

    async def status(self) -> BackendStatus: ...

    async def send_text(self, target_username: str, text: str, operation_id: str) -> SendResult: ...


class SenderError(Exception):
    """A fixed public error code with no private paths or message content."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
