"""Synthetic large media: real archive, MCP client, private exports and PDF worker."""
import asyncio
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile

import pytest
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject

from tests.support.proof import proof_case
from tests.support.encrypted import Engine
from tests.integration.test_importer import factory
from wechat_bridge.archive.importer import refresh_archive
from wechat_bridge.core.errors import BridgeError
from wechat_bridge.mcp.server import create_server
from wechat_bridge.mcp.service import ToolService


def pdf_bytes(*, large=False, blank=False, encrypted=False):
    writer = PdfWriter()
    for phrase in ('Page one fictional invoice', 'Page two delivery details', 'Page three final terms'):
        page = writer.add_blank_page(width=612, height=792)
        if not blank:
            font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                     NameObject('/Subtype'): NameObject('/Type1'),
                                     NameObject('/BaseFont'): NameObject('/Helvetica')})
            page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): writer._add_object(font)})})
            content = DecodedStreamObject()
            content.set_data(f'BT /F1 12 Tf 50 700 Td ({phrase}) Tj ET'.encode())
            page[NameObject('/Contents')] = writer._add_object(content)
    if large:
        # Valid unused streams produce a genuinely >8 MiB PDF without huge page text.
        for _ in range(9):
            unused = DecodedStreamObject(); unused.set_data(b'x' * (1024 * 1024))
            writer._add_object(unused)
    if encrypted:
        writer.encrypt('fictional-test-password')
    result = io.BytesIO(); writer.write(result)
    return result.getvalue()


def media_case(tmp_path, data):
    case = proof_case(tmp_path)
    file = case.config.account_root / 'msg/file/2023-11/test.bin'
    file.write_bytes(data)
    digest = hashlib.md5(data).hexdigest()
    with Engine(case.config.account_root / 'db_storage/message/message_resource.db') as writer:
        writer.run(f'UPDATE MessageResourceDetail SET size={len(data)} WHERE resource_id=4')
    with Engine(case.config.account_root / 'db_storage/hardlink/hardlink.db') as writer:
        writer.run(f"UPDATE file_hardlink_info_v4 SET file_size={len(data)},md5='{digest}'")
    refresh_archive(case.config, adapter_factory=factory)
    service = ToolService(case.config)
    aid = service.queries.list_attachments(kind='file')['items'][0]['attachment_id']
    return case, service, aid


def test_large_pdf_real_stdio_export_and_paginated_text(tmp_path):
    raw = pdf_bytes(large=True)
    assert len(raw) > 8 * 1024 * 1024
    case, _, aid = media_case(tmp_path, raw)
    parameters = StdioServerParameters(command=sys.executable,
        args=['-m', 'wechat_bridge.cli', '--state-dir', str(case.config.state_dir), 'serve', '--no-watch'])
    async def scenario():
        async with asyncio.timeout(30):
            async with Client(stdio_client(parameters)) as client:
                preview = await client.call_tool('get_attachment', {'attachment_id': aid})
                assert preview.is_error and preview.structured_content['error'] == 'content_too_large'
                assert 'export_attachment' in preview.structured_content['next_action']
                exported = await client.call_tool('export_attachment', {'attachment_id': aid})
                assert not exported.is_error
                meta = exported.structured_content
                assert meta['exported'] and not meta['external_upload']
                assert meta['mime_type'] == 'application/pdf' and meta['size'] == len(raw)
                assert all(b.type == 'text' for b in exported.content)
                path = Path(meta['local_path'])
                assert path.parent == case.config.state_dir / 'exports'
                assert path.read_bytes() == raw
                assert meta['export_sha256'] == hashlib.sha256(raw).hexdigest()
                assert stat.S_IMODE(path.stat().st_mode) == 0o400
                assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
                first = await client.call_tool('read_pdf_attachment', {'attachment_id': aid, 'page_count': 1})
                assert not first.is_error, first
                text = first.structured_content
                assert text['total_pages'] == 3
                assert text['pages'][0]['text'].strip() == 'Page one fictional invoice'
                assert text['next_page'] == 2
                second = await client.call_tool('read_pdf_attachment', {'attachment_id': aid, 'start_page': 2, 'page_count': 2})
                assert not second.is_error
                assert [p['page'] for p in second.structured_content['pages']] == [2, 3]
                assert second.structured_content['next_page'] is None
                assert len(list(path.parent.iterdir())) == 1
    asyncio.run(scenario())


def test_pdf_continuation_never_skips_truncated_page(tmp_path):
    _, service, aid = media_case(tmp_path, pdf_bytes())
    first = service.pdf(aid, max_characters=8, page_count=1)
    assert first['next_page'] == 1 and first['next_character_offset'] == 8
    second = service.pdf(aid, start_page=1, character_offset=8, page_count=1)
    assert first['pages'][0]['text'] + second['pages'][0]['text'] == 'Page one fictional invoice'
    assert second['next_page'] == 2


def test_repeated_pdf_pages_use_same_verified_snapshot_without_rehash(tmp_path, monkeypatch):
    _, service, aid = media_case(tmp_path, pdf_bytes())
    service.pdf(aid, page_count=1)
    import wechat_bridge.attachments.export as module
    def no_new_resolve(*args, **kwargs):
        raise AssertionError('Source must not be rehashed for another page of this snapshot')
    monkeypatch.setattr(module, 'resolve_attachment', no_new_resolve)
    assert service.pdf(aid, start_page=2, page_count=1)['pages'][0]['page'] == 2


@pytest.mark.parametrize('arguments', [dict(start_page=0), dict(page_count=11), dict(max_characters=50001),
                                       dict(character_offset=-1), dict(page_count=True)])
def test_pdf_request_bounds_before_export(tmp_path, arguments):
    case, service, aid = media_case(tmp_path, pdf_bytes())
    with pytest.raises(BridgeError):
        service.pdf(aid, **arguments)
    assert not (case.config.state_dir / 'exports').exists()


def test_encrypted_scanned_invalid_and_non_pdf_are_explicit(tmp_path):
    _, service, aid = media_case(tmp_path / 'encrypted', pdf_bytes(encrypted=True))
    with pytest.raises(BridgeError, match='pdf_encrypted'):
        service.pdf(aid)
    _, service, aid = media_case(tmp_path / 'scan', pdf_bytes(blank=True))
    result = service.pdf(aid)
    assert not result['text_available'] and result['ocr_performed'] is False
    assert 'no extractable text' in result['next_action']
    _, service, aid = media_case(tmp_path / 'invalid', b'%PDF-1.7\ninvalid')
    with pytest.raises(BridgeError, match='pdf_invalid'):
        service.pdf(aid)
    _, service, aid = media_case(tmp_path / 'notpdf', b'not a PDF')
    with pytest.raises(BridgeError, match='attachment_not_pdf'):
        service.pdf(aid)


def test_export_partial_failure_publishes_nothing_and_removes_temp(tmp_path, monkeypatch):
    case, service, aid = media_case(tmp_path, b'x' * (9 * 1024 * 1024))
    import wechat_bridge.attachments.export as module
    def fail(source, destination, *args):
        destination.write(source.read(1234))
        raise BridgeError('source_changed')
    monkeypatch.setattr(module, '_copy_verified', fail)
    with pytest.raises(BridgeError, match='source_changed'):
        service.export(aid)
    assert list((case.config.state_dir / 'exports').iterdir()) == []


def test_export_source_change_during_copy_fails_integrity(tmp_path, monkeypatch):
    case, service, aid = media_case(tmp_path, b'x' * (9 * 1024 * 1024))
    import wechat_bridge.attachments.export as module
    original = module._copy_verified
    def changed(source, destination, *args):
        with (case.config.account_root / 'msg/file/2023-11/test.bin').open('r+b') as writer:
            writer.write(b'y')
        return original(source, destination, *args)
    monkeypatch.setattr(module, '_copy_verified', changed)
    with pytest.raises(BridgeError, match='source_changed'):
        service.export(aid)
    assert list((case.config.state_dir / 'exports').iterdir()) == []


def test_export_symlink_directory_and_destination_cannot_escape(tmp_path):
    case, service, aid = media_case(tmp_path, b'fictional file')
    outside = tmp_path / 'outside'; outside.mkdir()
    exportdir = case.config.state_dir / 'exports'
    exportdir.symlink_to(outside, target_is_directory=True)
    with pytest.raises(BridgeError, match='unsafe_state_path'):
        service.export(aid)
    assert list(outside.iterdir()) == []
    exportdir.unlink(); exportdir.mkdir(mode=0o700)
    target = outside / 'target'; target.write_bytes(b'do not overwrite')
    name = hashlib.sha256(b'fictional file').hexdigest() + '.bin'
    (exportdir / name).symlink_to(target)
    with pytest.raises(BridgeError, match='export_write_failed'):
        service.export(aid)
    assert target.read_bytes() == b'do not overwrite'
    assert not list(exportdir.glob('.pending-*'))


def test_cached_export_mutation_is_never_read_as_verified_pdf(tmp_path):
    _, service, aid = media_case(tmp_path, pdf_bytes())
    metadata, _ = service.export(aid)
    path = Path(metadata['local_path']); path.chmod(0o600)
    path.write_bytes(b'%PDF-1.7\nchanged')
    with pytest.raises(BridgeError, match='export_integrity_failed'):
        service.pdf(aid)


def test_export_exceeds_cap_preflight_no_hash_or_copy(tmp_path, monkeypatch):
    case, service, aid = media_case(tmp_path, b'fictional file')
    import wechat_bridge.attachments.resolver as module
    monkeypatch.setattr(module, 'MAX_FILE_BYTES', 4)
    monkeypatch.setattr(module, 'hash_stream', lambda *a: pytest.fail('oversize file was hashed'))
    with pytest.raises(BridgeError, match='export_too_large'):
        service.export(aid)
    assert not (case.config.state_dir / 'exports').exists()


def test_missing_file_has_download_action_without_export(tmp_path):
    case, service, aid = media_case(tmp_path, b'fictional file')
    (case.config.account_root / 'msg/file/2023-11/test.bin').unlink()
    result, exported = service.export(aid)
    assert exported is None and result['availability'] == 'not_local'
    assert 'Download' in result['next_action']


def test_pdf_worker_timeout_kills_and_reaps_own_child(tmp_path, monkeypatch):
    import wechat_bridge.attachments.pdf as module
    real_popen = module.subprocess.Popen; children = []
    def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs); children.append(child); return child
    monkeypatch.setattr(module.subprocess, 'Popen', capture)
    monkeypatch.setattr(module, 'PDF_TIMEOUT_SECONDS', 0.1)
    with tempfile.TemporaryFile() as stream, tempfile.TemporaryFile() as output:
        with pytest.raises(BridgeError, match='pdf_processing_timeout'):
            module._run_worker([sys.executable, '-c', 'import time; time.sleep(10)'], stream.fileno(), output)
    assert len(children) == 1 and children[0].poll() is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(children[0].pid, os.WNOHANG)


def test_pdf_worker_memory_limit_kills_and_reaps(tmp_path, monkeypatch):
    import wechat_bridge.attachments.pdf as module
    real_popen = module.subprocess.Popen; children = []
    def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs); children.append(child); return child
    monkeypatch.setattr(module.subprocess, 'Popen', capture)
    monkeypatch.setattr(module, '_resident_bytes', lambda pid: 0 if pid == os.getpid() else module.MAX_WORKER_RESIDENT_BYTES + 1)
    with tempfile.TemporaryFile() as stream, tempfile.TemporaryFile() as output:
        with pytest.raises(BridgeError, match='pdf_processing_limit'):
            module._run_worker([sys.executable, '-c', 'import time; time.sleep(10)'], stream.fileno(), output)
    assert children[0].poll() is not None


def test_mcp_export_rejects_destination_paths_and_traversal_without_echo(tmp_path):
    case, _, aid = media_case(tmp_path, b'fictional file')
    async def scenario():
        async with Client(create_server(case.config, watch=False)) as client:
            for name, args in [
                ('export_attachment', {'attachment_id': aid, 'destination': '/tmp/unapproved'}),
                ('export_attachment', {'attachment_id': '../../outside'}),
                ('read_pdf_attachment', {'attachment_id': aid, 'page_count': 11}),
                ('read_pdf_attachment', {'attachment_id': aid, 'character_offset': -1}),
            ]:
                result = await client.call_tool(name, args)
                assert result.is_error and result.structured_content == {'error': 'invalid_arguments'}
            assert not (case.config.state_dir / 'exports').exists()
    asyncio.run(scenario())


def test_pdf_compressed_stream_limit_rejected_before_text_extraction(tmp_path):
    writer = PdfWriter(); page = writer.add_blank_page(width=612, height=792)
    stream = DecodedStreamObject(); stream.set_data(b' ' * (9 * 1024 * 1024))
    page[NameObject('/Contents')] = writer._add_object(stream.flate_encode())
    data = io.BytesIO(); writer.write(data)
    assert len(data.getvalue()) < 20000
    _, service, aid = media_case(tmp_path, data.getvalue())
    with pytest.raises(BridgeError, match='pdf_processing_limit'):
        service.pdf(aid)


def test_pdf_worker_crash_reports_no_text_and_releases_service_slot(tmp_path, monkeypatch):
    _, service, aid = media_case(tmp_path, pdf_bytes())
    import wechat_bridge.attachments.pdf as module
    monkeypatch.setattr(module, '_run_worker', lambda *args: -9)
    with pytest.raises(BridgeError, match='pdf_processing_limit'):
        service.pdf(aid)
    assert service._pdf_slot.acquire(blocking=False)
    service._pdf_slot.release()


def test_export_name_ignores_untrusted_filename_and_invalid_source_path(tmp_path):
    from dataclasses import replace
    from wechat_bridge.attachments.export import export_attachment
    case, service, aid = media_case(tmp_path, b'fictional file')
    ref, generation = service.queries.attachment_ref(aid)
    metadata, _ = export_attachment(replace(ref, original_filename='../../outside/evil.pdf'), generation, case.config, 'source')
    assert Path(metadata['local_path']).name == hashlib.sha256(b'fictional file').hexdigest() + '.bin'
    bad, exported = export_attachment(replace(ref, relative_path='../../outside/evil.pdf'), generation, case.config, 'source')
    assert exported is None and bad['availability'] == 'identity_mismatch'


def test_slow_pdf_extraction_keeps_mcp_event_loop_responsive(tmp_path, monkeypatch):
    import threading
    import time
    case, _, aid = media_case(tmp_path, pdf_bytes())
    started = threading.Event()
    original = ToolService.pdf
    def slow(self, *args, **kwargs):
        started.set(); time.sleep(0.5)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(ToolService, 'pdf', slow)
    async def scenario():
        async with Client(create_server(case.config, watch=False)) as client:
            pending = asyncio.create_task(client.call_tool('read_pdf_attachment', {'attachment_id': aid}))
            while not started.is_set():
                await asyncio.sleep(0.01)
            response = await asyncio.wait_for(client.call_tool('list_contacts', {}), timeout=0.2)
            assert not response.is_error and not pending.done()
            assert not (await pending).is_error
    asyncio.run(scenario())


def test_pdf_memory_monitor_tolerates_child_exit_transition(tmp_path, monkeypatch):
    import wechat_bridge.attachments.pdf as module
    def missing_child(pid):
        if pid == os.getpid():
            return 0
        raise BridgeError('pdf_memory_guard_unavailable')
    monkeypatch.setattr(module, '_resident_bytes', missing_child)
    with tempfile.TemporaryFile() as stream, tempfile.TemporaryFile() as output:
        assert module._run_worker([sys.executable, '-c', 'pass'], stream.fileno(), output) == 0


def test_pdf_memory_monitor_persistent_failure_kills_child(tmp_path, monkeypatch):
    import wechat_bridge.attachments.pdf as module
    real_popen = module.subprocess.Popen; children = []
    def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs); children.append(child); return child
    def missing_child(pid):
        if pid == os.getpid():
            return 0
        raise BridgeError('pdf_memory_guard_unavailable')
    monkeypatch.setattr(module.subprocess, 'Popen', capture)
    monkeypatch.setattr(module, '_resident_bytes', missing_child)
    with tempfile.TemporaryFile() as stream, tempfile.TemporaryFile() as output:
        with pytest.raises(BridgeError, match='pdf_memory_guard_unavailable'):
            module._run_worker([sys.executable, '-c', 'import time; time.sleep(10)'], stream.fileno(), output)
    assert children[0].poll() is not None
