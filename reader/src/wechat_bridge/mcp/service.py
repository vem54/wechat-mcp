"""Verified bounded bytes and safe status, independently of protocol encoding."""
from collections import OrderedDict
from functools import cached_property
import threading

from ..archive.importer import archive_status
from ..attachments.resolver import resolve_attachment, MAX_FILE_BYTES
from ..attachments.export import export_attachment, open_snapshot
from ..attachments.pdf import read_pdf, validate_request, MAX_PDF_PAGES_PER_CALL, MAX_PDF_CHARACTERS
from ..attachments.preview import make_preview, validate_preview, DEFAULT_PREVIEW_EDGE, DEFAULT_PREVIEW_BYTES
from ..core.config import Config, read_private_json, reject_symlinks
from ..core.errors import BridgeError
from ..core.limits import DEFAULT_RECORDS, MAX_RECORDS, MAX_CONTEXT_NEIGHBORS, MAX_QUERY_CHARACTERS
from ..search.repository import QueryRepository
from ..core.validate import require_int_range
from ..source.keys import load_manifest

DEFAULT_CONTENT_BYTES = 1048576
MAX_CONTENT_BYTES = 8388608


class ToolService:
    """Query and attachment operations behind the MCP tools; read-only, bounded, redacted status."""
    def __init__(self, config: Config):
        self.config = config
        self._exports = OrderedDict()
        self._export_lock = threading.RLock()
        self._pdf_slot = threading.BoundedSemaphore(1)
        self._image_slot = threading.BoundedSemaphore(1)

    @cached_property
    def queries(self):
        """Repository over the archive, created on first use."""
        return QueryRepository(self.config)

    # Reads at most 64 proof files; the newest live proof wins.
    def _acceptance(self) -> dict:
        root = self.config.state_dir / 'proofs'
        reject_symlinks(root, 'unsafe_state_path')
        paths = []
        for path in root.glob('*.json'):
            paths.append(path)
            if len(paths) > 64:
                return {'status': 'unavailable', 'diagnostic_code': 'proof_inventory_limit'}
        for path in sorted(paths, key=lambda p: p.stat().st_mtime_ns, reverse=True):
            value = read_private_json(path)
            if value.get('proof_scope') == 'live':
                return {'status': value.get('status', 'unavailable'),
                        'expectation_basis': value.get('expectation_basis', 'unknown'),
                        'checks': value.get('checks', {})}
        return {'status': 'not_attested'}

    def status(self) -> dict:
        """Archive status, key count, acceptance state and public limits; carries no key material or paths."""
        from ..cli import doctor
        result = archive_status(self.config)
        try:
            count = len(load_manifest(self.config.state_dir / 'keys.json').entries)
            key_error = None
        except BridgeError as error:
            count, key_error = None, error.code
        try:
            acceptance = self._acceptance()
        except (BridgeError, OSError):
            acceptance = {'status': 'unavailable'}
        return result | {'source': 'local_mac_history', 'read_only': True,
                         'environment': doctor(self.config.state_dir),
                         'saved_key_count': count, 'saved_key_error': key_error,
                         'source_acceptance': acceptance,
                         'limits': {'default_records': DEFAULT_RECORDS, 'maximum_records': MAX_RECORDS,
                                    'context_neighbors': MAX_CONTEXT_NEIGHBORS, 'query_characters': MAX_QUERY_CHARACTERS,
                                    'default_content_bytes': DEFAULT_CONTENT_BYTES,
                                    'maximum_content_bytes': MAX_CONTENT_BYTES,
                                    'maximum_local_export_bytes': MAX_FILE_BYTES,
                                    'maximum_pdf_pages_per_call': MAX_PDF_PAGES_PER_CALL,
                                    'maximum_pdf_characters': MAX_PDF_CHARACTERS},
                         'attachment_workflow': {'large_files': 'export_attachment', 'pdf_text': 'read_pdf_attachment', 'image_preview': 'get_image_preview',
                             'storage': 'private_local_state', 'external_upload': False, 'ocr': False},
                         'continuous_updates': {'requires': ['Background archive watcher or open MCP reader with watching enabled', 'Mac awake',
                             'WeChat logged in and receiving messages'], 'source': 'available local files',
                             'business_summary_updates': 'The connected AI must request and process new records.'},
                         'image_decoding': {'supported': ['JPEG', 'PNG', 'WEBP', 'legacy_XOR', 'V1_DAT', 'V2_DAT'],
                                            'unsupported': ['animated', 'WXGF', 'HEVC']}}

    def attachment(self, attachment_id: str, *, representation: str = 'auto', max_bytes: int = DEFAULT_CONTENT_BYTES, generation: int | None = None) -> tuple:
        """Return (metadata, bytes or None) for one attachment, at most max_bytes.

        Raises invalid_content_limit, invalid_representation, unsupported_representation or content_too_large.
        """
        require_int_range(max_bytes, 1, MAX_CONTENT_BYTES, 'invalid_content_limit')
        if representation not in ('auto', 'source', 'decoded'):
            raise BridgeError('invalid_representation')
        ref, generation = self.queries.attachment_ref(attachment_id, generation=generation)
        content = ('decoded' if ref.kind == 'image' else 'source') if representation == 'auto' else representation
        if content == 'decoded' and ref.kind != 'image':
            raise BridgeError('unsupported_representation')
        with resolve_attachment(ref, self.config, decode=content == 'decoded',
                                max_source_bytes=max_bytes if content == 'source' else None) as result:
            metadata = {'attachment_id': ref.attachment_id, 'message_id': ref.message_id, 'kind': ref.kind,
                        'generation': generation, 'original_filename': ref.original_filename,
                        'availability': result.availability, 'representation': result.representation,
                        'content_representation': content, 'diagnostic_code': result.diagnostic_code,
                        'source_sha256': result.source_sha256, 'decoded_sha256': result.decoded_sha256,
                        'verification_basis': result.verification_basis, 'decoded_available': result.decoded is not None,
                        'mime_type': 'application/octet-stream', 'resource_uri': None}
            if result.handle is None:
                return metadata, None
            if content == 'decoded':
                data = result.decoded.data
                if len(data) > max_bytes:
                    raise BridgeError('content_too_large')
                metadata |= {'mime_type': {'PNG': 'image/png', 'JPEG': 'image/jpeg', 'WEBP': 'image/webp'}[result.decoded.format],
                             'width': result.decoded.width, 'height': result.decoded.height,
                             'decoder_version': result.decoded.decoder_version}
            else:
                data = result.handle.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise BridgeError('content_too_large')
            metadata |= {'size': len(data), 'resource_uri': f'wechat-attachment://content/{generation}/{attachment_id}/{content}'}
            return metadata, data

    def export(self, attachment_id: str, *, representation: str = 'auto', generation: int | None = None):
        """Create/reuse a private immutable local snapshot, never an inline binary response."""
        if representation not in ('auto', 'source', 'decoded'):
            raise BridgeError('invalid_representation')
        ref, selected_generation = self.queries.attachment_ref(attachment_id, generation=generation)
        content = ('decoded' if ref.kind == 'image' else 'source') if representation == 'auto' else representation
        if content == 'decoded' and ref.kind != 'image':
            raise BridgeError('unsupported_representation')
        key = (attachment_id, selected_generation, content)
        # A retained snapshot is explicitly tied to its archive generation. Repeated
        # page reads verify its descriptor identity, not rehash the entire source.
        with self._export_lock:
            cached = self._exports.get(key)
            if cached is not None:
                with open_snapshot(cached):
                    pass
                self._exports.move_to_end(key)
                return cached.metadata.copy(), cached
            metadata, exported = export_attachment(ref, selected_generation, self.config, content)
            if exported is not None:
                self._exports[key] = exported
                if len(self._exports) > 16:
                    self._exports.popitem(last=False)
            return metadata, exported

    def pdf(self, attachment_id: str, *, start_page=1, page_count=5, max_characters=20000,
            character_offset=0, generation: int | None = None):
        """Read bounded PDF text locally. Scans and encrypted files remain explicit."""
        validate_request(start_page, page_count, max_characters, character_offset)
        metadata, exported = self.export(attachment_id, representation='source', generation=generation)
        if exported is None:
            return metadata | {'text_available': False, 'ocr_performed': False}
        if not self._pdf_slot.acquire(blocking=False):
            raise BridgeError('pdf_busy')
        try:
            return read_pdf(exported, start_page=start_page, page_count=page_count,
                            max_characters=max_characters, character_offset=character_offset)
        finally:
            self._pdf_slot.release()

    def image_preview(self, attachment_id: str, *, max_edge=DEFAULT_PREVIEW_EDGE,
                      max_bytes=DEFAULT_PREVIEW_BYTES, crop=None, generation: int | None = None):
        """Create a labeled bounded image, preserving the source and full-resolution export."""
        validate_preview(max_edge, max_bytes, crop)
        if not self._image_slot.acquire(blocking=False):
            raise BridgeError('image_preview_busy')
        try:
            ref, selected_generation = self.queries.attachment_ref(attachment_id, generation=generation)
            if ref.kind != 'image':
                raise BridgeError('attachment_not_image')
            with resolve_attachment(ref, self.config, decode=True) as result:
                metadata = {'attachment_id': ref.attachment_id, 'message_id': ref.message_id,
                    'generation': selected_generation, 'kind': ref.kind,
                    'availability': result.availability, 'representation': result.representation,
                    'diagnostic_code': result.diagnostic_code, 'source_sha256': result.source_sha256,
                    'decoded_sha256': result.decoded_sha256, 'verification_basis': result.verification_basis,
                    'preview_only': True, 'original_export_available': False, 'preview_available': False,
                    'original_dimensions': None, 'resource_uri': None}
                if result.handle is None or result.decoded is None:
                    metadata['next_action'] = ('Download the image in WeChat, then allow the archive to refresh.'
                        if result.availability == 'not_local' else
                        'This image cannot be decoded safely. Use export_attachment with representation="source" for its encoded bytes.')
                    return metadata, None
                dimensions = {'width': result.decoded.width, 'height': result.decoded.height}
                preview, data = make_preview(result.decoded, max_edge=max_edge, max_bytes=max_bytes, crop=crop)
                metadata |= preview | {'preview_available': True, 'source_dimensions': dimensions,
                    'original_dimensions': dimensions if result.representation == 'original' else None,
                    'original_export_available': result.representation == 'original',
                    'source_export_available': True,
                    'export_tool_arguments': {'attachment_id': attachment_id, 'representation': 'decoded',
                                               'generation': selected_generation},
                    'next_action': 'This is a resized preview. Use a pixel crop to inspect a region, or export_attachment for the full source image. Thumbnails do not provide an original.'}
                return metadata, data
        finally:
            self._image_slot.release()
