"""Bounded AI-visible image previews; large fictional fixtures, no account data."""
import asyncio
import base64
import hashlib
import io

from mcp import Client
from PIL import Image
import pytest

from tests.support.proof import proof_case
from tests.support.encrypted import Engine
from tests.integration.test_importer import factory
from wechat_bridge.archive.importer import refresh_archive
from wechat_bridge.attachments.images import decode_image
from wechat_bridge.attachments.preview import make_preview
from wechat_bridge.core.errors import BridgeError
from wechat_bridge.mcp.server import create_server
from wechat_bridge.mcp.service import ToolService


def image_case(tmp_path, data):
    case = proof_case(tmp_path)
    case.image_path.write_bytes(data)
    with Engine(case.config.account_root / 'db_storage/message/message_resource.db') as writer:
        writer.run(f'UPDATE MessageResourceDetail SET size={len(data)} WHERE resource_id=3')
    refresh_archive(case.config, adapter_factory=factory)
    service = ToolService(case.config)
    aid = service.queries.list_attachments(kind='image')['items'][0]['attachment_id']
    return case, service, aid


def encoded_image(*, large=False, noise=False):
    image = (Image.effect_noise((1800, 1800), 100).convert('RGB') if noise
             else Image.new('RGB', (1800, 1800) if large else (100, 80), (30, 60, 90)))
    buffer = io.BytesIO(); image.save(buffer, 'PNG', compress_level=0 if large else 6)
    return buffer.getvalue()


def test_large_image_preview_is_inline_bounded_and_original_unchanged(tmp_path):
    raw = encoded_image(large=True)
    assert len(raw) > 8 * 1024 * 1024
    case, service, aid = image_case(tmp_path, raw)
    before = hashlib.sha256(case.image_path.read_bytes()).hexdigest()
    async def scenario():
        async with Client(create_server(case.config, watch=False)) as client:
            original = await client.call_tool('get_attachment', {'attachment_id': aid, 'max_bytes': 8388608})
            assert original.is_error and 'get_image_preview' in original.structured_content['next_action']
            reply = await client.call_tool('get_image_preview', {'attachment_id': aid})
            assert not reply.is_error, reply
            meta = reply.structured_content
            assert meta['preview_only'] and meta['reencoded'] and meta['preview_available']
            assert meta['original_export_available'] and meta['source_export_available']
            assert meta['original_dimensions'] == {'width': 1800, 'height': 1800}
            assert meta['preview_dimensions'] == {'width': 1600, 'height': 1600}
            assert meta['source_sha256'] == before
            images = [block for block in reply.content if block.type == 'image']
            assert len(images) == 1
            data = base64.b64decode(images[0].data)
            assert len(data) <= 1048576 and len(data) == meta['size']
            assert hashlib.sha256(data).hexdigest() == meta['preview_sha256']
            with Image.open(io.BytesIO(data)) as preview:
                assert preview.size == (1600, 1600)
            exported = await client.call_tool('export_attachment', meta['export_tool_arguments'])
            assert not exported.is_error
            assert exported.structured_content['export_sha256'] == before
    asyncio.run(scenario())
    assert hashlib.sha256(case.image_path.read_bytes()).hexdigest() == before
    assert service.queries.list_attachments(kind='image')['items'][0]['attachment_id'] == aid


def test_noisy_photo_enforces_tiny_budget_without_upscaling():
    raw = encoded_image(large=True, noise=True)
    decoded = decode_image(io.BytesIO(raw), material=None)
    metadata, data = make_preview(decoded, max_edge=1600, max_bytes=16384)
    assert len(data) <= 16384 and metadata['mime_type'] == 'image/jpeg'
    assert metadata['preview_dimensions']['width'] <= 1600
    assert metadata['preview_dimensions']['height'] <= 1600


def test_crop_is_explicit_pixel_region_and_never_enlarged(tmp_path):
    _, service, aid = image_case(tmp_path, encoded_image())
    meta, data = service.image_preview(aid, crop=[10, 20, 60, 70])
    assert meta['crop'] == [10, 20, 60, 70]
    assert meta['preview_dimensions'] == {'width': 50, 'height': 50}
    assert meta['original_dimensions'] == {'width': 100, 'height': 80}
    assert meta['crop_coordinates'] == 'orientation_corrected_source_pixels'
    with Image.open(io.BytesIO(data)) as image:
        assert image.size == (50, 50)


@pytest.mark.parametrize('crop', [[-1, 0, 2, 2], [0, 0, 101, 80], [0, 0, 0, 1],
                                 [0, 0, 2], [0, 0, 2, 3, 4], [False, 0, 2, 2], [0, 0, 2.0, 2]])
def test_invalid_crops_rejected(tmp_path, crop):
    _, service, aid = image_case(tmp_path, encoded_image())
    with pytest.raises(BridgeError, match='invalid_preview_crop'):
        service.image_preview(aid, crop=crop)


@pytest.mark.parametrize('options', [dict(max_edge=63), dict(max_edge=2049), dict(max_edge=True),
                                    dict(max_bytes=16383), dict(max_bytes=1048577)])
def test_preview_size_limits(tmp_path, options):
    _, service, aid = image_case(tmp_path, encoded_image())
    with pytest.raises(BridgeError):
        service.image_preview(aid, **options)


def test_exif_orientation_applied_without_exporting_exif_or_original_mutation():
    source = Image.new('RGB', (100, 80), (10, 20, 30))
    exif = Image.Exif(); exif[274] = 6; exif[270] = 'fictional-private-comment'
    buffer = io.BytesIO(); source.save(buffer, 'JPEG', exif=exif)
    original = buffer.getvalue()
    decoded = decode_image(io.BytesIO(original), material=None)
    metadata, data = make_preview(decoded)
    assert metadata['oriented_dimensions'] == {'width': 80, 'height': 100}
    assert metadata['preview_dimensions'] == {'width': 80, 'height': 100}
    with Image.open(io.BytesIO(data)) as preview:
        assert not preview.getexif() and not preview.info.get('exif')
    assert decoded.data == original


def test_thumbnail_preview_never_claims_original_dimensions_or_export(tmp_path, monkeypatch):
    _, service, aid = image_case(tmp_path, encoded_image())
    from dataclasses import replace
    ref, generation = service.queries.attachment_ref(aid)
    monkeypatch.setattr(service.queries, 'attachment_ref', lambda *a, **k: (replace(ref, representation='thumbnail'), generation))
    metadata, _ = service.image_preview(aid)
    assert metadata['representation'] == 'thumbnail'
    assert metadata['original_dimensions'] is None and metadata['original_export_available'] is False
    assert metadata['source_dimensions'] == {'width': 100, 'height': 80}


def test_unsupported_image_reports_no_preview_and_source_export_action(tmp_path):
    _, service, aid = image_case(tmp_path, b'wxgf' + b'fictional opaque payload')
    meta, data = service.image_preview(aid)
    assert data is None and meta['preview_available'] is False
    assert meta['original_export_available'] is False
    assert 'representation="source"' in meta['next_action']


def test_missing_image_reports_download_action(tmp_path):
    case, service, aid = image_case(tmp_path, encoded_image())
    case.image_path.unlink()
    meta, data = service.image_preview(aid)
    assert data is None and meta['availability'] == 'not_local'
    assert 'Download' in meta['next_action']


def test_preview_mcp_rejects_invalid_arguments_without_echo(tmp_path):
    case, _, aid = image_case(tmp_path, encoded_image())
    async def scenario():
        async with Client(create_server(case.config, watch=False)) as client:
            for extra in ({'crop': [0, 0, 2]}, {'max_bytes': 8388608}, {'crop': [False, 0, 2, 3]}, {'destination': '/tmp/private'}):
                reply = await client.call_tool('get_image_preview', {'attachment_id': aid} | extra)
                assert reply.is_error and reply.structured_content == {'error': 'invalid_arguments'}
            reply = await client.call_tool('get_image_preview', {'attachment_id': aid, 'crop': [0, 0, 101, 80]})
            assert reply.is_error and reply.structured_content['error'] == 'invalid_preview_crop'
    asyncio.run(scenario())


def test_preview_busy_and_nonimage_release_slot(tmp_path):
    _, service, aid = image_case(tmp_path, encoded_image())
    assert service._image_slot.acquire(blocking=False)
    with pytest.raises(BridgeError, match='image_preview_busy'):
        service.image_preview(aid)
    service._image_slot.release()
    file_id = service.queries.list_attachments(kind='file')['items'][0]['attachment_id']
    with pytest.raises(BridgeError, match='attachment_not_image'):
        service.image_preview(file_id)
    assert service._image_slot.acquire(blocking=False)
    service._image_slot.release()


def test_preview_preserves_existing_decoder_pixel_guard(tmp_path, monkeypatch):
    import wechat_bridge.attachments.images as images
    _, service, aid = image_case(tmp_path, encoded_image())
    monkeypatch.setattr(images, 'MAX_PIXELS', 100)
    metadata, data = service.image_preview(aid)
    assert data is None and metadata['diagnostic_code'] == 'image_dimensions_limit'
    assert not metadata['preview_available']


def test_preview_cpu_work_runs_off_mcp_event_loop(tmp_path, monkeypatch):
    import threading
    import time
    case, _, aid = image_case(tmp_path, encoded_image())
    started = threading.Event(); original = ToolService.image_preview
    def slow(self, *args, **kwargs):
        started.set(); time.sleep(0.5)
        return original(self, *args, **kwargs)
    monkeypatch.setattr(ToolService, 'image_preview', slow)
    async def scenario():
        async with Client(create_server(case.config, watch=False)) as client:
            pending = asyncio.create_task(client.call_tool('get_image_preview', {'attachment_id': aid}))
            while not started.is_set():
                await asyncio.sleep(0.01)
            reply = await asyncio.wait_for(client.call_tool('list_contacts', {}), timeout=0.2)
            assert not reply.is_error and not pending.done()
            assert not (await pending).is_error
    asyncio.run(scenario())


@pytest.mark.parametrize('mode,color,transparent', [('L', 0, 0), ('RGB', (10, 20, 30), (10, 20, 30))])
def test_png_trns_alpha_survives_metadata_stripping(mode, color, transparent):
    source = Image.new(mode, (8, 8), color)
    output = io.BytesIO(); source.save(output, 'PNG', transparency=transparent)
    raw = output.getvalue()
    decoded = decode_image(io.BytesIO(raw), material=None)
    metadata, data = make_preview(decoded)
    assert metadata['mime_type'] == 'image/png'
    assert metadata['transparency_flattened_to_white'] is False
    with Image.open(io.BytesIO(data)) as preview:
        assert preview.convert('RGBA').getpixel((0, 0))[3] == 0
    assert decoded.data == raw
