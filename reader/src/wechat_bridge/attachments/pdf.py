"""Bounded page extraction in a disposable child; no external service or OCR."""
import ctypes
from functools import lru_cache
import json
import os
import subprocess
import sys
import tempfile
import time

from ..core.errors import BridgeError
from ..core.validate import require_int_range
from .export import open_snapshot

MAX_PDF_PAGES_PER_CALL = 10
MAX_PDF_CHARACTERS = 50000
PDF_TIMEOUT_SECONDS = 20
MAX_WORKER_OUTPUT = 400000
MAX_WORKER_RESIDENT_BYTES = 512 * 1024 * 1024


@lru_cache(maxsize=1)
def _mac_proc_info():
    library = ctypes.CDLL('/usr/lib/libproc.dylib')
    function = library.proc_pidinfo
    function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    function.restype = ctypes.c_int
    return function


def _resident_bytes(pid):
    if sys.platform != 'darwin':
        return 0  # Linux child enforces RLIMIT_AS itself.
    # Darwin sys/proc_info.h: proc_taskinfo is six uint64 followed by twelve int32.
    buffer = ctypes.create_string_buffer(96)
    try:
        count = _mac_proc_info()(pid, 4, 0, buffer, len(buffer))
    except (OSError, AttributeError):
        raise BridgeError('pdf_memory_guard_unavailable') from None
    if count != len(buffer):
        raise BridgeError('pdf_memory_guard_unavailable')
    return int.from_bytes(buffer.raw[8:16], sys.byteorder)


def _run_worker(command, descriptor, output):
    # Fail closed before launching if this platform cannot observe its own child.
    _resident_bytes(os.getpid())
    process = subprocess.Popen(command, pass_fds=(descriptor,), stdout=output, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + PDF_TIMEOUT_SECONDS
    missing_samples = 0
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise BridgeError('pdf_processing_timeout')
            try:
                resident = _resident_bytes(process.pid)
            except BridgeError:
                # Darwin can stop exposing task info just before waitpid can
                # reap a fast-exiting child. Give that transition one bounded
                # wait; persistent failure still kills the worker closed.
                try:
                    process.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    missing_samples += 1
                    if missing_samples >= 3:
                        raise BridgeError('pdf_memory_guard_unavailable') from None
                    continue
            missing_samples = 0
            if resident > MAX_WORKER_RESIDENT_BYTES:
                raise BridgeError('pdf_processing_limit')
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
        return process.returncode
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()  # Every path reaps the child; no abandoned PDF worker.


def validate_request(start_page, page_count, max_characters, character_offset):
    require_int_range(start_page, 1, 100000, 'invalid_pdf_page')
    require_int_range(page_count, 1, MAX_PDF_PAGES_PER_CALL, 'invalid_pdf_page_count')
    require_int_range(max_characters, 1, MAX_PDF_CHARACTERS, 'invalid_pdf_character_limit')
    require_int_range(character_offset, 0, 1000000, 'invalid_pdf_character_offset')


def read_pdf(exported, *, start_page=1, page_count=5, max_characters=20000, character_offset=0):
    validate_request(start_page, page_count, max_characters, character_offset)
    if exported.metadata['mime_type'] != 'application/pdf':
        raise BridgeError('attachment_not_pdf')
    # Pass the verified descriptor, never an arbitrary path supplied by a caller.
    with open_snapshot(exported) as stream, tempfile.TemporaryFile() as output:
        command = [sys.executable, '-m', 'wechat_bridge.attachments.pdf_worker', str(stream.fileno()),
                   str(start_page), str(page_count), str(max_characters), str(character_offset)]
        returncode = _run_worker(command, stream.fileno(), output)
        output.seek(0)
        raw = output.read(MAX_WORKER_OUTPUT + 1)
        if returncode != 0 or len(raw) > MAX_WORKER_OUTPUT:
            raise BridgeError('pdf_processing_limit')
        try:
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError
        except (ValueError, UnicodeError):
            raise BridgeError('pdf_processing_failed') from None
        if result.get('error'):
            code = result['error']
            allowed = {'pdf_encrypted', 'pdf_invalid', 'pdf_page_out_of_range', 'pdf_processing_limit',
                       'pdf_dependency_unavailable', 'invalid_pdf_character_offset'}
            raise BridgeError(code if code in allowed else 'pdf_processing_failed')
        continuation = None
        if result.get('next_page') is not None:
            continuation = {'attachment_id': exported.metadata['attachment_id'],
                'generation': exported.metadata['generation'], 'start_page': result['next_page'],
                'character_offset': result['next_character_offset'], 'page_count': page_count,
                'max_characters': max_characters}
        return exported.metadata | result | {'next_arguments': continuation}
