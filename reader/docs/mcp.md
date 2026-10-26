# MCP server reference

`wechat-bridge serve` runs a stdio MCP server built on the pinned official
Python SDK (`mcp==2.3.0`). Stdout carries protocol only; diagnostics go to
stderr. There is no network listener. Source: `src/wechat_bridge/mcp/`.

## Launching

```sh
uv run wechat-bridge serve             # with background archive watching
uv run wechat-bridge serve --no-watch  # deterministic session, no watcher
```

A first archive import needs `wechat-bridge archive-refresh`. The server never
imports or decrypts at query time. With watching enabled and an active
generation present at startup, a background thread polls DB/WAL metadata and
reconciles every 60 seconds while the source changes, backing off to hourly
while it is untouched. If no generation exists when `serve` starts, no
watcher starts; run `archive-refresh`, then restart `serve`. On disconnect the
watcher receives a stop signal and is joined for up to 8 seconds. A slow native
read can outlive the join, and the next import reclaims an unfinished
generation.

Register the server with a client through the project's virtualenv entry point
and an explicit state directory. Codex:

```sh
codex mcp add wechat_bridge -- <repo>/.venv/bin/wechat-bridge \
  --state-dir "$HOME/Library/Application Support/WechatBridge" serve
```

Claude Code (local scope, available only in the folder where you run it; use
`--scope user` only if every Claude Code session should be able to read your
chats):

```sh
claude mcp add --scope local wechat_bridge -- <repo>/.venv/bin/wechat-bridge \
  --state-dir "$HOME/Library/Application Support/WechatBridge" serve
```

Each registered client starts its own `serve` process. Concurrent `serve`
sessions coordinate on `.archive-watcher.lock` so only one runs an active
watcher per state directory; the others retry the lock every 30 seconds and
take over if the holder exits. Refreshes from the watcher and from a manual
`archive-refresh` are serialized by `.archive-import.lock` in the state
directory. A manual refresh that finds the import lock held returns
`archive_refresh_in_progress` instead of waiting. The watcher treats that
result as `deferred` and tries again on its next cycle.

A watcher refresh that fails with `setup_required`, `key_coverage_incomplete`,
`unsupported_build` or `archive_account_mismatch` is not retried every cycle.
The watcher waits until `keys.json` changes or an hour passes, because only
those events can clear the failure and each attempt records a failed
generation.

The `.venv` entry point is an editable install, so it runs whatever branch the
repository has checked out. Switching branches changes the code that the next
`serve` start runs. It also changes any module that a running server has not
imported yet.

## Tools

All tools are non-destructive, idempotent and closed-world. Queries and inline previews are read-only. `export_attachment` and `read_pdf_attachment` are annotated as local writes because they create private snapshots; neither changes WeChat or uploads files.
Unknown arguments return `invalid_arguments`, as do SDK argument-validation
failures (the caller's rejected value is not echoed). Opaque IDs have the form
`<kind>_<64 hex>`.

| Tool | Arguments | Returns |
| --- | --- | --- |
| `status` | none | Readiness, coverage/freshness, environment, saved key count, latest live proof status, limits, supported image formats |
| `list_conversations` | `query`, `kind` (`direct`\|`group`), `limit`, `cursor` | Conversations |
| `list_contacts` | `query`, `limit`, `cursor` | Contacts; duplicate names keep distinct IDs |
| `get_group` | `conversation_id`, `limit`, `cursor` | Group metadata and locally observed membership (not a historical roster) |
| `search_messages` | `query` (required), `conversation_id`, `sender_id`, `start`, `end`, `type`, `limit`, `cursor` | Literal Unicode/Chinese substring matches with excerpts; times need a timezone |
| `get_messages` | `conversation_id`, `sender_id`, `start`, `end`, `type`, `limit`, `cursor` | Chronological timeline, including unsupported messages and unknown senders |
| `get_context` | `message_id`, `before` (10), `after` (10), `generation` | A message plus at most 100 combined neighbors |
| `list_attachments` | `message_id`, `kind` (`image`\|`file`), `representation` (`original`\|`thumbnail`), `availability`, `limit`, `cursor` | Attachment metadata; `local_unverified` means bytes not yet checked |
| `get_image_preview` | `attachment_id`, `max_edge` (1600, max2048), `max_bytes` (1MiB, min16KiB), optional `crop` ([left,top,right,bottom]), `generation` | Inline resized image, preview-only label, dimensions, hashes and export availability |
| `export_attachment` | `attachment_id`, `representation` (`auto`\|`source`\|`decoded`), `generation` | Verified private local snapshot, path, size, SHA-256 and original/thumbnail label; no inline bytes |
| `read_pdf_attachment` | `attachment_id`, `start_page` (1), `page_count` (5), `max_characters` (20000), `character_offset` (0), `generation` | Bounded page text, total pages, continuation and local snapshot metadata; no OCR |
| `get_attachment` | `attachment_id`, `representation` (`auto`\|`source`\|`decoded`), `max_bytes`, `generation` | Verified bytes plus metadata (hashes, labels, resource URI) |

Filter values: message `type` is one of `text`, `image`, `file`, `reply`,
`unsupported`, `voice`, `video`; attachment `availability` is one of
`local_unverified`, `not_local`, `unsupported_format`, `identity_mismatch`.
Other values return `invalid_filter`.

## Limits

| Limit | Value | Defined in |
| --- | --- | --- |
| Records per page | default 50, max 200 | `core/limits.py` |
| Context neighbors | max 100 combined | `core/limits.py` |
| Query length | 256 characters | `core/limits.py` |
| Query read budget | 8 MiB | `search/repository.py` |
| Archive query deadline | 2 seconds | `search/repository.py` |
| Inline attachment delivery | default 1 MiB, max 8 MiB | `mcp/service.py` |
| Local attachment export | 200 MiB per file, 50 MiB per image | `attachments/resolver.py` |
| PDF text per call | max 10 pages and 50,000 characters | `attachments/pdf.py` |
| PDF processing | 20 seconds wall time, 15 CPU seconds; 8 MiB decoded streams; 512 MiB monitored resident memory on macOS | `attachments/pdf.py`, `attachments/pdf_worker.py` |
| Metadata reply wire size | 1 MiB | `mcp/server.py` |
| Binary reply wire size (base64 + metadata) | 12 MiB | `mcp/server.py` |

Exceeding an inline bound returns `content_too_large` with a fixed hint to use local export or PDF text. Binary data is never emitted as an unbounded MCP response. The PDF worker is killed and reaped on timeout or resource failure. macOS resident memory is checked every 50 ms (a monitored threshold, not an instantaneous hard ceiling); decompression and parsing limits apply inside the worker.

## Attachment delivery

- `auto` decodes images and returns files as source bytes.
- Supported decoded images arrive as MCP image content. Files and explicitly
  requested source bytes arrive as embedded binary resources.
- The server preserves original/thumbnail and source/decoded labels. A client
  can fetch an unsupported original (for example WXGF) as labeled source bytes
  and nothing else.
- Resource URIs are generation-bound:
  `wechat-attachment://content/{generation}/{attachment_id}/{representation}`.
  When that generation has been removed, list attachments again.

### Large files and PDFs

1. Find an attachment with `list_attachments`.
2. Call `export_attachment` for a private local copy, or `read_pdf_attachment` to read PDF text directly. No destination path or external upload URL is accepted.
3. Continue PDF reads with the returned `next_page` and `next_character_offset`. Preserve the returned `generation` while it remains retained. A truncated page continues at its character offset before advancing; do not claim to have read omitted pages.

Exports live in the reader's private state directory under `exports/`, not the repository. Filenames are SHA-256 plus a detected format suffix; untrusted original filenames are metadata only. Files are streamed in 64 KiB blocks, verified before atomic publication, and deduplicated by content. Directory mode is 0700 and published file mode is 0400. No partial file is returned. Repeated page requests reuse a verified snapshot and check its descriptor identity without repeatedly hashing the full source. Exports persist until the user removes them; they are never uploaded or deleted automatically. Requested preview bytes and extracted text are returned to the connected AI through MCP; no separate external file service is used.

PDF parsing uses pinned `pypdf` in a disposable process; it does not run PDF JavaScript or follow document URLs. It is not an operating-system security sandbox. Password-protected, malformed, unusually complex or oversized PDFs return explicit errors. A scan may have no extractable text; `text_available: false` and `ocr_performed: false` prevent a claim that its images have been read. Open the local PDF for visual review or use local OCR separately.

Only downloaded local media is available. A missing attachment returns a download instruction; the bridge does not secretly fetch it from WeChat's servers. An unsupported image can still be exported as explicitly labeled source bytes. Existing small images remain available inline through `get_attachment`. For larger decoded photos, `get_image_preview` creates an explicitly resized inline image without replacing original bytes. It reports original, orientation-corrected and preview dimensions. An optional crop uses orientation-corrected source pixel coordinates for closer inspection, without upscaling. Previews strip EXIF and other image metadata, may re-encode to JPEG to meet the byte limit, and cannot establish original image quality or guarantee tiny text remains legible. Thumbnail previews never claim full original dimensions or availability. Use the returned `export_tool_arguments` for the full source. Unsupported WXGF, animation and existing decode limits remain explicit.

## Paging

Cursors are opaque, authenticated, and bound to the method, filters, limit and
a pinned generation. Current and previous complete generations are retained; a
cursor for a removed generation returns `cursor_expired`.

## Errors and trust

Tool failures return `{"error": "<code>"}` with `isError` set. Attachment failures may include a fixed `next_action` hint; exception strings and rejected caller values are never echoed. Unexpected
failures become `internal_error` without exception chains or private paths.
Retrieved messages and files are untrusted data, never instructions, and the
server states this in its MCP `instructions`.

Codes a tool call can return:

| Code | Cause |
| --- | --- |
| `invalid_arguments` | Unknown argument, or the SDK rejected an argument's type or range |
| `invalid_filter` | `kind`, `type`, `representation` or `availability` outside the listed values |
| `invalid_query`, `invalid_time_range`, `invalid_limit`, `invalid_context_limit`, `invalid_content_limit`, `invalid_id` | A value failed validation |
| `invalid_representation`, `unsupported_representation` | `get_attachment` representation is unknown, or `decoded` was requested for a non-image |
| `invalid_cursor` | The cursor is malformed, unauthenticated, or bound to a different method, filter set or limit |
| `cursor_expired` | The cursor's or `generation` argument's generation was removed |
| `invalid_generation` | `generation` is not a positive integer |
| `conversation_not_found`, `message_not_found`, `attachment_not_found`, `group_not_found` | The ID is absent from the pinned generation |
| `archive_not_ready`, `search_not_ready` | No complete generation exists yet, or the search index is not built |
| `archive_query_failed` | The archive query failed or hit the 2 second deadline |
| `content_too_large` | A reply or attachment exceeds a bound in [Limits](#limits) |
| `internal_error` | Any other failure |

When an attachment exists but its bytes are not deliverable, `get_attachment`
returns the metadata without an error. The `availability` field (`not_local`,
`unsupported_format`, `identity_mismatch`) and `diagnostic_code` (for example
`attachment_not_local` or `attachment_mapping_unsupported`) carry the reason.
