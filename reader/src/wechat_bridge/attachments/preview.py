"""Explicit, bounded visual previews; never replace verified original bytes."""
import hashlib
import io

from PIL import Image, ImageOps

from ..core.errors import BridgeError
from ..core.validate import require_int_range

DEFAULT_PREVIEW_EDGE = 1600
MAX_PREVIEW_EDGE = 2048
DEFAULT_PREVIEW_BYTES = 1048576
MIN_PREVIEW_BYTES = 16384
MAX_PREVIEW_BYTES = 1048576


def validate_preview(max_edge, max_bytes, crop):
    require_int_range(max_edge, 64, MAX_PREVIEW_EDGE, 'invalid_preview_edge')
    require_int_range(max_bytes, MIN_PREVIEW_BYTES, MAX_PREVIEW_BYTES, 'invalid_preview_limit')
    if crop is not None:
        if (not isinstance(crop, (list, tuple)) or len(crop) != 4
                or any(type(value) is not int or not 0 <= value <= 40000000 for value in crop)
                or crop[2] <= crop[0] or crop[3] <= crop[1]):
            raise BridgeError('invalid_preview_crop')


def make_preview(decoded, *, max_edge=DEFAULT_PREVIEW_EDGE, max_bytes=DEFAULT_PREVIEW_BYTES, crop=None):
    """Resize already validated static bytes; crop coordinates use displayed orientation.

    The existing decoder has already checked byte, pixel, raster and static-format
    limits. Encoding strips EXIF/metadata, and never touches source files.
    """
    validate_preview(max_edge, max_bytes, crop)
    try:
        with Image.open(io.BytesIO(decoded.data)) as source:
            oriented = ImageOps.exif_transpose(source)
            try:
                oriented_dimensions = {'width': oriented.width, 'height': oriented.height}
                if crop is not None and (crop[2] > oriented.width or crop[3] > oriented.height):
                    raise BridgeError('invalid_preview_crop')
                selected = oriented.crop(tuple(crop)) if crop is not None else oriented.copy()
            finally:
                oriented.close()
        try:
            # PNG tRNS transparency may live in metadata for P, L or RGB.
            # Materialize its alpha before resizing or stripping metadata.
            if 'transparency' in selected.info:
                converted = selected.convert('RGBA'); selected.close(); selected = converted
            # Never enlarge a thumbnail or a cropped region.
            selected.thumbnail((max_edge, max_edge), Image.Resampling.LANCZOS)
            if selected.mode not in ('RGB', 'RGBA', 'L', 'LA', 'P', '1'):
                converted = selected.convert('RGB'); selected.close(); selected = converted
            selected.info.clear()  # Do not carry source EXIF, GPS, comments or profiles.
            output = io.BytesIO(); selected.save(output, 'PNG')
            data = output.getvalue()
            mime = 'image/png'; transparency_flattened = False
            if len(data) > max_bytes:
                # JPEG is the bounded photo fallback. Transparency is explicitly
                # flattened to white; metadata makes this transformation visible.
                transparency_flattened = 'A' in selected.getbands() or 'transparency' in selected.info
                rgba = selected.convert('RGBA')
                rgb = Image.new('RGB', selected.size, 'white')
                rgb.paste(rgba, mask=rgba.getchannel('A')); rgba.close()
                selected.close(); selected = rgb
                mime = 'image/jpeg'
                for _ in range(12):
                    output = io.BytesIO(); selected.save(output, 'JPEG', quality=85)
                    data = output.getvalue()
                    if len(data) <= max_bytes:
                        break
                    width, height = max(1, selected.width * 3 // 4), max(1, selected.height * 3 // 4)
                    smaller = selected.resize((width, height), Image.Resampling.LANCZOS)
                    selected.close(); selected = smaller
                else:
                    raise BridgeError('preview_budget_exceeded')
            return {'mime_type': mime, 'size': len(data), 'preview_only': True, 'reencoded': True,
                    'oriented_dimensions': oriented_dimensions,
                    'preview_dimensions': {'width': selected.width, 'height': selected.height},
                    'crop': list(crop) if crop is not None else None,
                    'crop_coordinates': 'orientation_corrected_source_pixels',
                    'transparency_flattened_to_white': transparency_flattened,
                    'preview_sha256': hashlib.sha256(data).hexdigest()}, data
        finally:
            selected.close()
    except (OSError, ValueError, Image.DecompressionBombWarning, Image.DecompressionBombError):
        raise BridgeError('image_preview_failed') from None
