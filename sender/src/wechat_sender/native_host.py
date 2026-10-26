"""Own a temporary, signed app copy and a private native bridge. No UI automation.

`prepare` never starts an app. `run` requires the ordinary client to be closed.
Only the explicitly created copy can be launched or stopped here. The original
application signature and the existing reader are never modified.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

from .archive import ArchiveReader
from .backend import DEFAULT_STATE, MAX_FRAME, RECIPIENT_POLICY, socket_filename
from .backend_protocol import SenderError
from .compatibility import inspect_app, validate_profile
from .protocol import text_message
from .ledger import Ledger, fingerprint
from .deployment import DEPLOYMENT_FINGERPRINT

ORIGINAL_APP = Path("/Applications/WeChat.app")
DEFAULT_ARCHIVE = Path.home() / "Library/Application Support/WechatBridge/archive.sqlite3"


def command(args, timeout=20):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout).stdout


def private_dir(path: Path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("unsafe_state_path")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid():
        raise ValueError("unsafe_state_owner")
    os.chmod(path, 0o700)


def running_clients() -> bool:
    result = subprocess.run(["/usr/bin/pgrep", "-x", "WeChat"], capture_output=True, timeout=5)
    if result.returncode not in (0, 1):
        raise ValueError("process_inspection_failed")
    return result.returncode == 0


def prepare(state: Path, profile: dict):
    private_dir(state)
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(ORIGINAL_APP)], 60)
    before = validate_profile(ORIGINAL_APP, profile)
    copy = state / "WeChat-Sender.app"
    if copy.exists():
        validate_profile(copy, profile)
        return {"status": "prepared", "copy_exists": True, "original_unchanged": True}
    command(["/bin/cp", "-cR", str(ORIGINAL_APP), str(copy)], 180)
    entitlements = state / "debug-copy.entitlements"
    import plistlib
    with entitlements.open("wb") as stream:
        plistlib.dump({"com.apple.security.get-task-allow": True,
                      "com.apple.security.cs.disable-library-validation": True,
                      "com.apple.security.cs.allow-jit": True,
                      "com.apple.security.cs.allow-unsigned-executable-memory": True}, stream)
    os.chmod(entitlements, 0o600)
    command(["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--entitlements",
             str(entitlements), str(copy)], 120)
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(copy)], 60)
    validate_profile(copy, profile)
    if before != inspect_app(ORIGINAL_APP):
        raise ValueError("original_app_changed")
    return {"status": "prepared", "copy_exists": True, "original_unchanged": True}


class NativeRuntime:
    def __init__(self, args, profile):
        self.args, self.profile = args, profile
        self.archive = ArchiveReader(args.reader_archive)
        self.script = None
        self.session = None
        self.device = None
        self.pid = None
        self.started_identity = None
        self.owns_process = False
        self.spawn_resumed = False
        self.events = {}
        self.pending_operations = set()
        self.pending_refresh_offset = 0
        self.native_observations = {}
        self.journal = Ledger(args.state / "native-outbox.sqlite3")
        self.lock = asyncio.Lock()
        self.errors = []
        self.stop_requested = False
        self.stop_event = asyncio.Event()
        self.startup_diagnostic = "native_starting"
        config = args.reader_archive.parent / "config.json"
        # Account location only; no identity secret or database keys are opened.
        self.account_root = Path(json.loads(config.read_text())["account_root"]).resolve()
        self.account_id = self.archive.account_id()

    def on_message(self, message, _data):
        if message.get("type") == "error":
            self.errors.append("native_script_error")
            return
        payload = message.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("task_id"), int):
            self.events[payload["task_id"]] = payload
        # Ordinary traffic and script logs are never persisted or printed.

    def identity(self):
        if self.pid is None:
            return None
        result = command(["/bin/ps", "-p", str(self.pid), "-o", "lstart=", "-o", "comm="], 5)
        return hashlib.sha256(result).hexdigest()

    def bound_account(self):
        try:
            if self.identity() != self.started_identity:
                return False
            data = command(["/usr/sbin/lsof", "-n", "-P", "-a", "-p", str(self.pid), "-Fn"], 10)
            opened = {Path(line[1:].decode()).resolve() for line in data.splitlines()
                      if line.startswith(b"n/") and b"/db_storage/" in line}
            expected = self.account_root / "db_storage"
            if not opened or not any(p.is_relative_to(expected) for p in opened):
                return False
            if any("xwechat_files" in str(p) and not p.is_relative_to(expected) for p in opened):
                return False
            return self.archive.account_id() == self.account_id
        except (OSError, ValueError, subprocess.SubprocessError):
            return False

    def verify_attach_target(self):
        """Bind attachment to an explicitly identified copy, never arbitrary WeChat."""
        if type(self.args.attach_pid) is not int or self.args.attach_pid <= 0 or not self.args.expected_identity:
            raise ValueError("attach_identity_required")
        self.pid = self.args.attach_pid
        self.started_identity = self.args.expected_identity
        executable = Path(command(["/bin/ps", "-p", str(self.pid), "-o", "comm="], 5).decode().strip()).resolve()
        expected = (self.args.state / "WeChat-Sender.app/Contents/MacOS/WeChat").resolve()
        if executable != expected or self.identity() != self.started_identity:
            raise ValueError("attach_process_identity_mismatch")
        if not self.bound_account():
            raise ValueError("native_account_not_verified")

    def load_script(self):
        pipeline = self.args.prepared_sender and self.profile.get("native_pipeline", {}).get("enabled") is True
        if self.args.prepared_sender and not pipeline and not getattr(self.args, "legacy_research", False):
            raise ValueError("native_pipeline_not_enabled")
        name = "native_pipeline_sender.js" if pipeline else "native_prepared_sender.js" if self.args.prepared_sender else "native_text.js"
        source = "const PROFILE = " + json.dumps(self.profile) + ";\n"
        if pipeline:
            library = Path(__file__).with_name("native_pipeline.dylib")
            if library.is_symlink() or not library.is_file() or hashlib.sha256(library.read_bytes()).hexdigest() != self.profile["native_pipeline"].get("library_sha256"):
                raise ValueError("native_pipeline_library_mismatch")
            source += "const PIPELINE_LIBRARY_PATH = " + json.dumps(str(library.resolve())) + ";\n"
        source += Path(__file__).with_name(name).read_text()
        self.script = self.session.create_script(source, name="wechat-sender-native")
        self.script.on("message", self.on_message)
        self.script.load()
        if self.args.prepared_sender:
            self.script.exports_sync.prepare()

    def attach(self):
        copy = self.args.state / "WeChat-Sender.app"
        validate_profile(copy, self.profile)
        command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(copy)], 60)
        self.verify_attach_target()
        import frida
        self.device = frida.get_local_device()
        self.session = self.device.attach(self.pid)
        # Recheck after attaching so a process switch cannot inherit the send gate.
        self.verify_attach_target()
        self.load_script()

    def launch(self):
        if running_clients():
            raise ValueError("close_wechat_before_test")
        copy = self.args.state / "WeChat-Sender.app"
        if not copy.exists():
            prepare(self.args.state, self.profile)
        validate_profile(copy, self.profile)
        command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(copy)], 60)
        # A same-volume copy preserves recovery data without altering the source.
        backup = self.args.state / ("before-native-trial-" + time.strftime("%Y%m%d-%H%M%S"))
        command(["/bin/cp", "-cR", str(self.account_root), str(backup)], 180)
        os.chmod(backup, 0o700)
        if running_clients():
            raise ValueError("close_wechat_before_test")
        import frida
        self.device = frida.get_local_device()
        self.pid = self.device.spawn([str(copy / "Contents/MacOS/WeChat")], stdio="pipe")
        # Record ownership before any fallible post-spawn call. Frida creates
        # the process suspended, so cleanup must also handle pre-resume errors.
        self.owns_process = True
        self.started_identity = self.identity()
        self.session = self.device.attach(self.pid)
        if not self.args.prepared_sender:
            self.load_script()
        self.device.resume(self.pid)
        self.spawn_resumed = True
        # The prepared sender requires the module and logged-in account. Its
        # startup loop loads/prepares it only after the resumed copy is bound.
        self.startup_diagnostic = "waiting_for_wechat_login" if self.args.prepared_sender else None

    async def startup(self):
        try:
            await asyncio.to_thread(self.attach if self.args.attach_pid is not None else self.launch)
        except Exception as error:
            self.startup_diagnostic = (str(error) if isinstance(error, ValueError)
                                       and str(error).replace("_", "").isalnum() else "native_start_failed")
            # A failed host must not remain a permanently reusable endpoint.
            # End it after safe cleanup; a later explicit start can try afresh.
            print(json.dumps({"status": "native_start_failed", "diagnostic_code": self.startup_diagnostic}), flush=True)
            self.stop_event.set()
            return
        while not self.stop_event.is_set():
            try:
                if await asyncio.to_thread(self.identity) != self.started_identity:
                    self.stop_event.set()
                    return
            except (OSError, subprocess.SubprocessError):
                self.stop_event.set()
                return
            if not self.stop_requested and self.args.prepared_sender and self.startup_diagnostic in {"native_starting", "waiting_for_wechat_login"}:
                await self.prepare_when_bound()
            await self.refresh_pending_operations()
            if self.stop_requested and await self.native_idle():
                self.stop_event.set()
                return
            await asyncio.sleep(1)

    async def prepare_when_bound(self):
        """Retry only pre-construction readiness failures, never failed native work."""
        if not await asyncio.to_thread(self.bound_account):
            self.startup_diagnostic = "waiting_for_wechat_login"
            return
        try:
            if self.script is None:
                await asyncio.to_thread(self.load_script)
                observed = await asyncio.to_thread(self.script.exports_sync.status)
            else:
                observed = await asyncio.to_thread(self.script.exports_sync.prepare)
            code = observed.get("diagnostic_code")
            if code in {"account_not_ready", "native_module_not_found"} and observed.get("can_detach") is True:
                self.startup_diagnostic = "waiting_for_wechat_login"
            else:
                self.startup_diagnostic = None
        except Exception:
            self.startup_diagnostic = "native_preparation_failed"

    async def status(self):
        host = {"managed": True, "owns_app": self.owns_process,
                "deployment_fingerprint": DEPLOYMENT_FINGERPRINT,
                "native_pipeline": self.args.prepared_sender and self.profile.get("native_pipeline", {}).get("enabled") is True,
                "stopping": self.stop_requested, "prepared_sender": self.args.prepared_sender,
                "profile_sha256": hashlib.sha256(json.dumps(self.profile, sort_keys=True).encode()).hexdigest(),
                "recipient_policy": RECIPIENT_POLICY}
        if self.stop_requested or self.startup_diagnostic and self.script is None:
            return {"ready": False, "identity_verified": False, "account_id": None,
                    "diagnostic_code": "native_stopping" if self.stop_requested else self.startup_diagnostic,
                    "host": host}
        try:
            observed = await asyncio.to_thread(self.script.exports_sync.status)
            bound = await asyncio.to_thread(self.bound_account)
            ready = (bound and not self.errors and observed.get("ready") is True
                     and (not self.args.prepared_sender or observed.get("sends_enabled") is True)
                     and self.args.enable_experimental_sending)
            return {"ready": ready, "identity_verified": bound,
                    "account_id": self.account_id if bound else None,
                    "diagnostic_code": None if ready else (
                        "native_script_error" if self.errors else
                        "native_account_not_verified" if not bound else
                        "native_work_in_progress" if observed.get("inflight_count", 0) else
                        "native_results_pending" if observed.get("operation_capacity_remaining") == 0 else
                        observed.get("diagnostic_code") or "native_probe_only"),
                    "probe": observed, "host": host}
        except Exception:
            return {"ready": False, "identity_verified": False, "account_id": None,
                    "diagnostic_code": "native_runtime_unavailable", "host": host}

    @staticmethod
    def submission_result(raw):
        """Accept evidence, never infer message acceptance from batch BaseResponse alone."""
        if not isinstance(raw, dict):
            return {"status": "outcome_unknown", "diagnostic_code": "invalid_native_result"}
        result = {"status": raw.get("status")}
        if result["status"] == "native_pipeline_completed":
            # This proves the correlated native send pipeline returned a local ID.
            # It does not independently prove an archive row, server acceptance,
            # UI visibility, or recipient delivery. Do not inherit server fields.
            proven_completion = (
                raw.get("completed") is True
                and type(raw.get("native_status")) is int and raw["native_status"] == 0
                and type(raw.get("native_error")) is int and raw["native_error"] == 0
                and type(raw.get("local_id")) is int and 0 < raw["local_id"] < 2**32
                and raw.get("recipient_correlated") is True
                and raw.get("request_correlated") is True
            )
            if not proven_completion:
                return {"status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}
            return {"status": "submitted", "diagnostic_code": "native_pipeline_completed",
                    "local_id": raw["local_id"], "local_history_evidence": "native_send_result"}
        elif result["status"] in {"acknowledged", "failed"}:
            proven_ack = (raw.get("server_ret_present") is True and type(raw.get("server_ret")) is int and raw["server_ret"] == 0
                          and raw.get("message_ret_present") is True and type(raw.get("message_ret")) is int and raw["message_ret"] == 0
                          and raw.get("message_correlated") is True)
            proven_rejection = ((raw.get("server_ret_present") is True and type(raw.get("server_ret")) is int and raw["server_ret"] != 0)
                                or (raw.get("message_ret_present") is True and type(raw.get("message_ret")) is int
                                    and raw["message_ret"] != 0 and raw.get("message_correlated") is True))
            if proven_ack:
                result = {"status": "submitted", "diagnostic_code": "server_acknowledged"}
            elif proven_rejection:
                result = {"status": "rejected", "diagnostic_code": "server_rejected"}
            else:
                result = {"status": "outcome_unknown", "diagnostic_code": "native_result_not_verified"}
        elif result["status"] not in {"submitted", "rejected", "outcome_unknown"}:
            result = {"status": "outcome_unknown", "diagnostic_code": "invalid_native_result"}
        elif isinstance(raw.get("diagnostic_code"), str):
            result["diagnostic_code"] = raw["diagnostic_code"]
        if type(raw.get("task_id")) is int and 0 < raw["task_id"] < 2**32:
            result["task_id"] = raw["task_id"]
        if isinstance(raw.get("server_id"), str) and raw["server_id"].isdigit():
            result["server_id"] = raw["server_id"]
        return result

    def observed_result(self, operation, raw, sequence=None):
        if sequence is not None:
            if (not isinstance(raw, dict) or raw.get("operation_known") is not True
                    or type(raw.get("dispatch_sequence")) is not int or raw["dispatch_sequence"] != sequence):
                return {"status": "outcome_unknown", "diagnostic_code": "native_operation_not_correlated"}
            self.native_observations[operation] = raw
        return self.submission_result(raw)

    async def wait_result(self, operation, initial, sequence=None):
        if initial.get("status") != "submitted" or initial.get("completed") is True or not self.args.prepared_sender:
            return self.observed_result(operation, initial, sequence)
        latest = initial
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            raw = await asyncio.to_thread(self.script.exports_sync.getresult, operation)
            if not isinstance(raw, dict):
                await asyncio.sleep(.1)
                continue
            latest = raw
            if raw.get("status") != "submitted" or raw.get("completed") is True:
                break
            await asyncio.sleep(.1)
        return self.observed_result(operation, latest, sequence)

    async def acknowledge_completion(self, operation, sequence):
        observed = self.native_observations.get(operation, {})
        if observed.get("completed") is not True:
            return
        try:
            record = self.journal.record(operation, account_id=self.account_id)
            expected = self.submission_result(observed)
            if (record is None or record["sequence"] != sequence or record["state"] == "dispatching"
                    or Ledger._evidence_rank(record["result"]) < Ledger._evidence_rank(expected)
                    or any(key in expected and record["result"].get(key) != expected[key]
                           for key in ("local_id", "server_id", "message_id"))):
                return
            answer = await asyncio.to_thread(self.script.exports_sync.acknowledge, operation, sequence)
            if isinstance(answer, dict) and answer.get("acknowledged") is True:
                self.pending_operations.discard(operation)
                self.native_observations.pop(operation, None)
        except Exception:
            pass  # Durable evidence exists; retry only this read/release handshake.

    async def observe_operation(self, operation):
        record = self.journal.record(operation, account_id=self.account_id)
        if record is None:
            return {"operation_known": False, "diagnostic_code": "operation_not_found"}
        result = record["result"]
        if (self.script is not None and operation in self.pending_operations
                and await asyncio.to_thread(self.bound_account)):
            try:
                raw = await asyncio.to_thread(self.script.exports_sync.getresult, operation)
                if isinstance(raw, dict) and raw.get("operation_known") is True:
                    observed = self.observed_result(operation, raw, record["sequence"])
                    result = self.journal.reconcile(record["operation_id"], observed)
                # A lost acknowledgement response may be followed by cache
                # eviction. The prior completed observation is already durable,
                # so its release handshake can safely be retried independently.
                await self.acknowledge_completion(operation, record["sequence"])
            except Exception:
                pass  # Never turn failed observation into a resend or weaker result.
        return {"operation_known": True, "operation_id": operation, "account_id": self.account_id, "result": result}

    async def refresh_pending_operations(self):
        if not self.pending_operations or self.lock.locked():
            return
        async with self.lock:
            pending = sorted(self.pending_operations)
            offset = self.pending_refresh_offset % len(pending)
            batch = (pending[offset:] + pending[:offset])[:8]
            self.pending_refresh_offset = (offset + len(batch)) % len(pending)
            for operation in batch:
                try:
                    await self.observe_operation(operation)
                except Exception:
                    # A transient archive/journal failure cannot terminate the
                    # lifetime monitor or authorize retrying a native submission.
                    continue

    async def native_idle(self):
        if self.script is None:
            return True
        try:
            state = await asyncio.to_thread(self.script.exports_sync.status)
            return (isinstance(state, dict) and type(state.get("inflight_count")) is int and state["inflight_count"] == 0
                    and state.get("native_pending_jobs", 0) == 0 and state.get("deferred_cleanup_count", 0) == 0)
        except Exception:
            return False

    async def dispatch(self, request):
        if request.get("reader_archive") != str(self.args.reader_archive.resolve()):
            return {"status": "rejected", "diagnostic_code": "reader_archive_mismatch"}
        if request.get("method") not in {"status", "stop"} and request.get("expected_deployment", DEPLOYMENT_FINGERPRINT) != DEPLOYMENT_FINGERPRINT:
            return {"status": "rejected", "diagnostic_code": "sender_upgrade_requires_restart"}
        if request.get("method") != "status" and "expected_profile" in request:
            expected = hashlib.sha256(json.dumps(self.profile, sort_keys=True).encode()).hexdigest()
            if (request["expected_profile"] != expected
                    or request.get("expected_recipient_policy", RECIPIENT_POLICY) != RECIPIENT_POLICY):
                return {"status": "rejected", "diagnostic_code": "running_host_configuration_mismatch"}
        if request.get("method") == "status":
            return await self.status()
        if request.get("method") == "stop":
            async with self.lock:
                self.stop_requested = True
                if self.script is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(self.script.exports_sync.disarm)
                idle = await self.native_idle()
                if idle:
                    self.stop_event.set()
                return {"status": "stopping", "waiting_for_app_exit": not self.owns_process and self.script is not None,
                        "waiting_for_native_completion": not idle}
        if request.get("method") == "get_operation":
            operation = request.get("operation_id")
            if not isinstance(operation, str) or not 1 <= len(operation) <= 128:
                return {"operation_known": False, "diagnostic_code": "invalid_operation_id"}
            if self.archive.account_id() != self.account_id:
                return {"operation_known": False, "diagnostic_code": "archive_account_mismatch"}
            async with self.lock:
                return await self.observe_operation(operation)
        if request.get("method") != "send_text":
            return {"status": "rejected", "diagnostic_code": "unknown_method"}
        async with self.lock:
            if self.stop_requested:
                return {"status": "rejected", "diagnostic_code": "native_stopping"}
            target = request.get("target_username")
            if not isinstance(target, str) or not target or len(target) > 512 or any(ord(c) < 32 for c in target):
                return {"status": "rejected", "diagnostic_code": "invalid_recipient_username"}
            operation = request.get("operation_id")
            if not isinstance(operation, str) or not 1 <= len(operation) <= 128:
                return {"status": "rejected", "diagnostic_code": "invalid_operation_id"}
            try:
                proto = text_message(target, request["text"]).hex()
                digest = fingerprint(target, request["text"])
            except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
                return {"status": "rejected", "diagnostic_code": "invalid_text"}
            try:
                prior = self.journal.lookup(operation, digest)
            except SenderError as error:
                return {"status": "rejected", "diagnostic_code": error.code}
            if prior:
                return prior | {"operation_id": operation}
            try:
                recipient = await asyncio.to_thread(self.archive.resolve_username, target,
                                                    expected_account_id=self.account_id)
            except SenderError as error:
                return {"status": "rejected", "diagnostic_code": error.code}
            state = await self.status()
            if not state["ready"]:
                return {"status": "rejected", "diagnostic_code": state["diagnostic_code"]}
            try:
                # Recheck after native account verification: refresh/account
                # changes must not swap a target between resolution and arming.
                current = await asyncio.to_thread(self.archive.resolve_username, target,
                                                  expected_account_id=self.account_id)
                # A contact may gain its first conversation during refresh;
                # both stored IDs refer to the same exact account/username.
                if (current.account_id, current.username) != (recipient.account_id, recipient.username):
                    return {"status": "rejected", "diagnostic_code": "archive_recipient_changed"}
            except SenderError as error:
                return {"status": "rejected", "diagnostic_code": error.code}
            try:
                pipeline = self.args.prepared_sender and self.profile.get("native_pipeline", {}).get("enabled") is True
                claim, sequence = None, None
                arm = {"recipient": target, "ttl_seconds": 60}
                if pipeline:
                    claim, prior = self.journal.claim(operation, digest, self.account_id,
                        "recipient_" + hashlib.sha256(target.encode()).hexdigest())
                    if prior:
                        return prior | {"operation_id": operation}
                    sequence = self.journal.record(operation, account_id=self.account_id)["sequence"]
                    if not 0 < sequence < 2**53:
                        self.journal.finish(claim, {"status": "rejected", "diagnostic_code": "native_sequence_exhausted"})
                        return {"status": "rejected", "diagnostic_code": "native_sequence_exhausted"}
                    arm.update(text=request["text"], operation_id=operation, dispatch_sequence=sequence)
                try:
                    armed = await asyncio.to_thread(self.script.exports_sync.arm, arm)
                except asyncio.CancelledError:
                    # Arm cannot submit a message. A failed/cancelled arm is a
                    # definite pre-dispatch rejection, unlike sendnative failure.
                    if claim is not None:
                        self.journal.finish(claim, {"status": "rejected", "diagnostic_code": "native_arm_rejected"})
                    raise
                except Exception:
                    result = {"status": "rejected", "diagnostic_code": "native_arm_rejected"}
                    if claim is not None:
                        self.journal.finish(claim, result)
                    return result
                if not isinstance(armed, dict) or armed.get("armed") is not True:
                    if claim is not None:
                        self.journal.finish(claim, {"status": "rejected", "diagnostic_code": "native_arm_rejected"})
                    return {"status": "rejected", "diagnostic_code": "native_arm_rejected"}
                # Native task IDs come from the native constructor. The durable operation
                # claim precedes its invocation and survives host restarts/unknown outcomes.
                if claim is None:
                    claim, prior = self.journal.claim(operation, digest, self.account_id,
                        "recipient_" + hashlib.sha256(target.encode()).hexdigest())
                    if prior:
                        return prior | {"operation_id": operation}
                try:
                    if pipeline:
                        self.pending_operations.add(operation)
                        result = await asyncio.to_thread(self.script.exports_sync.sendnative, target, request["text"], operation, sequence)
                    else:
                        result = await asyncio.to_thread(self.script.exports_sync.sendtext, 0, proto, operation)
                    result = await self.wait_result(operation, result, sequence)
                except BaseException:
                    self.journal.finish(claim, {"status": "outcome_unknown", "diagnostic_code": "native_outcome_unknown"})
                    raise
                self.journal.finish(claim, result)
                if pipeline:
                    await self.acknowledge_completion(operation, sequence)
                return result
            except Exception:
                return {"status": "outcome_unknown", "diagnostic_code": "native_outcome_unknown"}

    def matches_owned_process(self):
        if self.pid is None:
            return False
        if self.started_identity is not None:
            return self.identity() == self.started_identity
        # Only a freshly spawned, not-yet-resumed child can reach this fallback.
        # Never apply it to attachment-only sessions or arbitrary process names.
        if not self.owns_process or self.spawn_resumed:
            return False
        executable = Path(command(["/bin/ps", "-p", str(self.pid), "-o", "comm="], 5).decode().strip()).resolve()
        expected = (self.args.state / "WeChat-Sender.app/Contents/MacOS/WeChat").resolve()
        return executable == expected

    def close(self):
        # Attachment-only sessions never terminate the existing client. Disarm
        # new work and retain interception until every owned task can detach.
        if not getattr(self, "owns_process", True):
            if self.script is not None:
                with contextlib.suppress(Exception):
                    self.script.exports_sync.disarm()
            while self.script is not None:
                try:
                    if self.identity() != self.started_identity:
                        break
                    state = self.script.exports_sync.status()
                    if not self.args.prepared_sender or state.get("can_detach") is True:
                        self.script.unload()
                        break
                except subprocess.SubprocessError:
                    break  # Original process ended, so its native callbacks are gone.
                except Exception:
                    pass  # Unknown native lifetime is not permission to unload callbacks.
                time.sleep(.1)
            if self.session is not None:
                with contextlib.suppress(Exception):
                    self.session.detach()
            return
        try:
            owned = self.matches_owned_process()
        except (OSError, subprocess.SubprocessError):
            owned = False
        if owned:
            try:
                if not getattr(self, "spawn_resumed", True):
                    # A suspended child may not handle SIGTERM. Release Frida's
                    # spawn gate and OS suspension before terminating it.
                    with contextlib.suppress(Exception):
                        self.device.resume(self.pid)
                    os.kill(self.pid, signal.SIGCONT)
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            while True:
                time.sleep(.1)
                try:
                    if not self.matches_owned_process():
                        break
                except subprocess.CalledProcessError as error:
                    if error.returncode == 1:
                        break  # ps reports that the exact PID no longer exists.
                except (OSError, subprocess.SubprocessError):
                    continue  # A timeout is not proof that callbacks are gone.



async def handle_connection(reader, writer, runtime):
    """Malformed input is rejected; an interrupted send dispatch stays uncertain."""
    send_dispatch_started = False
    try:
        data = await asyncio.wait_for(reader.readline(), 5)
        if not data.endswith(b"\n") or len(data) >= MAX_FRAME:
            raise ValueError
        request = json.loads(data)
        if not isinstance(request, dict):
            raise ValueError
        send_dispatch_started = request.get("method") == "send_text"
        result = await runtime.dispatch(request)
    except Exception:
        result = ({"status": "outcome_unknown", "diagnostic_code": "native_dispatch_interrupted"}
                  if send_dispatch_started else
                  {"status": "rejected", "diagnostic_code": "invalid_native_request"})
    try:
        writer.write(json.dumps(result).encode() + b"\n")
        await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


async def run(args, profile):
    private_dir(args.state)
    socket = args.state / socket_filename(args.socket_name)
    # Exclusive process lock covers the socket before inspecting stale files.
    import fcntl
    lock_path = socket.with_suffix(".lock")
    lock = lock_path.open("a")
    os.chmod(lock_path, 0o600)
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    prepared_lock = None
    if args.prepared_sender:
        prepared_lock = (args.state / "prepared-host.lock").open("a")
        os.chmod(args.state / "prepared-host.lock", 0o600)
        fcntl.flock(prepared_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    if socket.exists():
        if not stat.S_ISSOCK(socket.lstat().st_mode):
            raise ValueError("unsafe_native_endpoint")
        socket.unlink()
    runtime = NativeRuntime(args, profile)
    startup = None
    loop = asyncio.get_running_loop()
    def stop_signal():
        # Complete any current request before app shutdown; no native retries.
        asyncio.create_task(runtime.dispatch({"method": "stop", "reader_archive": str(args.reader_archive.resolve())}))
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_signal)
    try:
        async def handle(reader, writer):
            await handle_connection(reader, writer, runtime)
        server = await asyncio.start_unix_server(handle, path=str(socket), limit=MAX_FRAME)
        os.chmod(socket, 0o600)
        print(json.dumps({"status": "native_probe_started", "sending_enabled": args.enable_experimental_sending}), flush=True)
        startup = asyncio.create_task(runtime.startup())
        async with server:
            await runtime.stop_event.wait()
    finally:
        runtime.stop_requested = True
        # A to_thread launch cannot be cancelled safely: wait until ownership of
        # any spawned process is recorded, then stop that exact process below.
        if startup is not None:
            await startup
        await asyncio.to_thread(runtime.close)
        if socket.exists():
            socket.unlink()
        lock.close()
        if prepared_lock is not None:
            prepared_lock.close()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "run"])
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--reader-archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--enable-experimental-sending", action="store_true")
    parser.add_argument("--prepared-sender", action="store_true")
    parser.add_argument("--legacy-research", action="store_true", help="Explicit research-only legacy transport; omits local chat history")
    parser.add_argument("--attach-pid", type=int)
    parser.add_argument("--expected-identity")
    parser.add_argument("--socket-name", default="native.sock")
    parser.add_argument("--allow-recipient", dest="obsolete_allow_recipient", action="append", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.obsolete_allow_recipient:
        print("Obsolete --allow-recipient ignored; all active archive recipients are available.", file=sys.stderr)
    socket_filename(args.socket_name)
    if (args.attach_pid is None) != (args.expected_identity is None):
        parser.error("--attach-pid and --expected-identity must be supplied together")
    profile = json.loads(args.profile.read_text())
    os.umask(0o077)
    if args.action == "prepare":
        print(json.dumps(prepare(args.state, profile)))
    else:
        asyncio.run(run(args, profile))


if __name__ == "__main__":
    main()
