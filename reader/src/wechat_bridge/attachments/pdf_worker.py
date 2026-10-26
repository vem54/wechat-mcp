"""Internal PDF worker. Reads one inherited fd; never opens URLs or attachments."""
import json
import logging
import os
import resource
import sys

MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_TEXT_PER_PAGE = 1000000


def extract(stream, start_page, page_count, max_characters, character_offset):
    from pypdf import PdfReader
    reader = PdfReader(stream, strict=True)
    if reader.is_encrypted:
        return {'error': 'pdf_encrypted'}
    total = len(reader.pages)
    if total > 100000:
        return {'error': 'pdf_processing_limit'}
    if start_page > total:
        return {'error': 'pdf_page_out_of_range'}
    pages = []; remaining = max_characters; next_page = None; next_offset = 0
    for number in range(start_page, min(start_page + page_count, total + 1)):
        page = reader.pages[number - 1]
        content = page.get_contents()
        if content is not None and len(content.get_data()) > MAX_STREAM_BYTES:
            return {'error': 'pdf_processing_limit'}
        text = page.extract_text() or ''
        if len(text) > MAX_TEXT_PER_PAGE:
            return {'error': 'pdf_processing_limit'}
        offset = character_offset if number == start_page else 0
        if offset > len(text):
            return {'error': 'invalid_pdf_character_offset'}
        selected = text[offset:offset + remaining]
        truncated = offset + len(selected) < len(text)
        pages.append({'page': number, 'text': selected, 'character_offset': offset,
                      'text_available': bool(text.strip()), 'truncated': truncated})
        remaining -= len(selected)
        if truncated:
            next_page, next_offset = number, offset + len(selected)
            break
        if remaining == 0:
            next_page = number + 1 if number < total else None
            break
    else:
        next_page = pages[-1]['page'] + 1 if pages and pages[-1]['page'] < total else None
    text_available = any(p['text_available'] for p in pages)
    return {'total_pages': total, 'pages': pages, 'text_available': text_available,
            'ocr_performed': False, 'next_page': next_page, 'next_character_offset': next_offset,
            'next_action': ('Continue with next_page and next_character_offset to read more text.'
                if text_available and next_page else 'Extracted the requested pages.' if text_available else
                'These pages have no extractable text. Open the local PDF for visual review or use local OCR; no OCR was performed.')}


def main():
    # CPU and output limits complement the parent's wall-clock timeout. They are
    # not a security sandbox: PDFs remain untrusted, and no PDF actions execute.
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_FSIZE, (400000, 400000))
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    logging.disable(logging.CRITICAL)
    try:
        from pypdf import overwrite_configuration
        from pypdf.errors import LimitReachedError
        overwrite_configuration(
            maximum_declared_stream_length=MAX_STREAM_BYTES,
            array_based_stream_maximum_output_length=MAX_STREAM_BYTES,
            jbig2_maximum_output_length=MAX_STREAM_BYTES,
            lzw_maximum_output_length=MAX_STREAM_BYTES,
            run_length_maximum_output_length=MAX_STREAM_BYTES,
            zlib_maximum_output_length=MAX_STREAM_BYTES,
            brotli_maximum_output_length=MAX_STREAM_BYTES,
            image_maximum_buffer_size=MAX_STREAM_BYTES,
            stream_decoding_work_maximum_length=4 * MAX_STREAM_BYTES,
            stream_parsing_work_maximum_count=200000,
            page_tree_maximum_entries=100000,
        )
        fd, start, count, maximum, offset = map(int, sys.argv[1:])
        with os.fdopen(fd, 'rb') as stream:
            result = extract(stream, start, count, maximum, offset)
    except ImportError:
        result = {'error': 'pdf_dependency_unavailable'}
    except (MemoryError, RecursionError, LimitReachedError):
        result = {'error': 'pdf_processing_limit'}
    except Exception:
        result = {'error': 'pdf_invalid'}
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
