"""Verified local snapshots; bounded streaming, private descriptors and atomic publication."""
from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import hashlib
import io
import os
from pathlib import Path
import secrets
import stat

from ..core.config import check_private_fd, ensure_private_dir, reject_symlinks
from ..core.errors import BridgeError
from .resolver import MAX_FILE_BYTES, file_identity, resolve_attachment

CHUNK_BYTES = 65536


@dataclass(frozen=True)
class ExportedAttachment:
    metadata: dict
    path: Path = field(repr=False)
    identity: tuple = field(repr=False)


def content_type(prefix: bytes) -> tuple[str, str]:
    if prefix.startswith(b'%PDF-'):
        return 'application/pdf', '.pdf'
    if prefix.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png', '.png'
    if prefix.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg', '.jpg'
    if prefix.startswith(b'RIFF') and prefix[8:12] == b'WEBP':
        return 'image/webp', '.webp'
    return 'application/octet-stream', '.bin'


@contextmanager
def _directory(config):
    # No caller-controlled destination or original filename enters the filesystem path.
    ensure_private_dir(config.state_dir)
    directory = config.state_dir / 'exports'
    ensure_private_dir(directory)
    reject_symlinks(directory, 'unsafe_state_path')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BridgeError('private_permissions')
        yield directory, fd
    finally:
        os.close(fd)


def _copy_verified(source, destination, expected_hash, expected_size=None):
    digest = hashlib.sha256(); size = 0
    while chunk := source.read(CHUNK_BYTES):
        size += len(chunk)
        if size > MAX_FILE_BYTES:
            raise BridgeError('export_too_large')
        destination.write(chunk)
        digest.update(chunk)
    if digest.hexdigest() != expected_hash or (expected_size is not None and size != expected_size):
        raise BridgeError('source_changed')
    return size


def _verify_existing(directory_fd, name, expected_hash, expected_size):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, 'rb') as stream:
        before = check_private_fd(stream.fileno())
        if before.st_size != expected_size:
            raise BridgeError('export_integrity_failed')
        digest = hashlib.sha256(); size = 0
        while chunk := stream.read(CHUNK_BYTES):
            size += len(chunk)
            if size > expected_size or size > MAX_FILE_BYTES:
                raise BridgeError('export_integrity_failed')
            digest.update(chunk)
        after = check_private_fd(stream.fileno())
        if file_identity(before) != file_identity(after) or digest.hexdigest() != expected_hash:
            raise BridgeError('export_integrity_failed')
        return file_identity(after)


def _publish(config, source, expected_hash, expected_size, suffix):
    temporary = None
    try:
        with _directory(config) as (directory, directory_fd):
            name = expected_hash + suffix
            temporary = '.pending-' + secrets.token_hex(16)
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
                with os.fdopen(fd, 'wb') as destination:
                    size = _copy_verified(source, destination, expected_hash, expected_size)
                    destination.flush()
                    os.fsync(destination.fileno())
                    # A published snapshot is read-only, including for its owner.
                    os.fchmod(destination.fileno(), 0o400)
                    try:
                        # Atomic, no overwrite, no follows: never expose partial bytes.
                        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                                follow_symlinks=False)
                        existing_identity = None
                    except FileExistsError:
                        existing_identity = _verify_existing(directory_fd, name, expected_hash, size)
                    os.unlink(temporary, dir_fd=directory_fd)
                    temporary = None
                    os.fsync(directory_fd)
                    # Identity comes from the exact verified descriptor. Never
                    # trust a newly stat'ed pathname after another process swaps it.
                    identity = existing_identity or file_identity(os.fstat(destination.fileno()))
                return directory / name, identity, size
            finally:
                if temporary is not None:
                    try:
                        os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
    except OSError as error:
        code = 'export_disk_full' if error.errno in (errno.ENOSPC, errno.EDQUOT) else 'export_write_failed'
        raise BridgeError(code) from None


def attachment_metadata(ref, generation, result, content):
    return {'attachment_id': ref.attachment_id, 'message_id': ref.message_id, 'kind': ref.kind,
            'generation': generation, 'original_filename': ref.original_filename,
            'availability': result.availability, 'representation': result.representation,
            'content_representation': content, 'diagnostic_code': result.diagnostic_code,
            'source_sha256': result.source_sha256, 'decoded_sha256': result.decoded_sha256,
            'verification_basis': result.verification_basis, 'decoded_available': result.decoded is not None,
            'mime_type': 'application/octet-stream', 'local_path': None, 'exported': False,
            'external_upload': False}


def export_attachment(ref, generation, config, content):
    try:
        with resolve_attachment(ref, config, decode=content == 'decoded') as result:
            metadata = attachment_metadata(ref, generation, result, content)
            if result.handle is None:
                metadata['next_action'] = ('Download this attachment in WeChat, then allow the local archive to refresh.'
                    if result.availability == 'not_local' else
                    'Try representation="source" to export the original encoded bytes.'
                    if result.availability == 'unsupported_format' and content == 'decoded' else
                    'Refresh the local archive and retry; mismatched bytes are never exported.')
                return metadata, None
            if content == 'decoded':
                source = io.BytesIO(result.decoded.data)
                digest, expected_size = result.decoded_sha256, len(result.decoded.data)
                metadata |= {'width': result.decoded.width, 'height': result.decoded.height,
                             'decoder_version': result.decoded.decoder_version}
            else:
                source, digest, expected_size = result.handle, result.source_sha256, ref.expected_size
            mime, suffix = content_type(source.read(16)); source.seek(0)
            path, identity, size = _publish(config, source, digest, expected_size, suffix)
            metadata |= {'exported': True, 'local_path': str(path), 'size': size, 'mime_type': mime,
                         'export_sha256': digest, 'snapshot': True,
                         'next_action': 'Use read_pdf_attachment for bounded page text, or open the local export.'
                         if mime == 'application/pdf' else 'Open the local export; it has not been uploaded.'}
            exported = ExportedAttachment(metadata.copy(), path, identity)
            return metadata, exported
    except BridgeError as error:
        if error.code == 'content_too_large':
            raise BridgeError('export_too_large') from None
        raise


@contextmanager
def open_snapshot(exported):
    reject_symlinks(exported.path, 'unsafe_state_path')
    fd = None
    try:
        fd = os.open(exported.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = check_private_fd(fd)
        if file_identity(info) != exported.identity:
            raise BridgeError('export_integrity_failed')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            yield stream
            if file_identity(os.fstat(stream.fileno())) != exported.identity:
                raise BridgeError('export_integrity_failed')
    except OSError:
        raise BridgeError('export_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)
