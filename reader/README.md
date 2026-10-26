# WeChat history reader

This MIT-licensed component is based on
[xerlxzx/Wechat-MCP](https://github.com/xerlxzx/Wechat-MCP). It searches locally
available WeChat history through a private archive and a stdio MCP server.
It cannot send messages. The separate [sender](../sender/README.md) can.

This fork adds private attachment export, paginated PDF text, bounded image
previews/crops, and signal-aware archive watching. The fork's live acceptance
used Apple Silicon, macOS 26.6.2 and WeChat 4.1.15 build 270135. Schema checks
also accept build 270102; other builds are refused.

## Install and set up

Run all commands below from this `reader/` directory. You need Python 3.14,
`uv`, SQLCipher 4 and Apple Command Line Tools.

```sh
brew install uv sqlcipher
uv sync --locked
uv run wechat-bridge doctor
uv run wechat-bridge discover
uv run wechat-bridge verify-keys
```

`discover` creates private configuration. If more than one account is found,
select the intended account as [setup documentation](docs/setup.md) describes.
Do not choose one silently. If saved database keys verify, reuse them.

If capture is required, first read [the full setup and recovery procedure](docs/setup.md).
It makes and locally signs a separate WeChat copy, uses Apple's debugger to
capture keys for the user's own account, and may require phone confirmation.
The original installed WeChat is not modified; no `sudo` or security-setting
changes are required. Obtain the account owner's permission for setup, have
them quit WeChat, and follow the returned plan ID:

```sh
uv run wechat-bridge setup prepare
uv run wechat-bridge setup run --plan-id <plan_id>
uv run wechat-bridge verify-keys
uv run wechat-bridge archive-refresh
uv run wechat-bridge archive-status
```

Do not run setup again for searches or ordinary refreshes. Never print or share
keys, the identity secret, capture files or account data. Follow recovery if a
setup step fails; do not kill an unrelated process by name.

## Connect a local MCP client

Point it at the absolute path to `reader/.venv/bin/wechat-bridge`, with arguments
`serve`. Default state is `~/Library/Application Support/WechatBridge`.

```sh
uv run wechat-bridge serve
```

The [MCP reference](docs/mcp.md) includes tool schemas, pagination, explicit
state paths and client examples. The initial archive must exist before serving.
The server's fallback watcher updates available source data in the background.
For sync independent of an AI client, run this separately under your preferred
local service manager:

```sh
uv run wechat-bridge archive-watch
```

Watchers share one owner lock, so multiple clients do not duplicate import work.
The command responds to SIGTERM/SIGINT and does not start or control WeChat.
This repository does not automatically install a login service. The Mac must
remain awake, with WeChat signed in and receiving messages.

## Tools and coverage

There are 12 tools: `status`, `list_conversations`, `list_contacts`, `get_group`,
`search_messages`, `get_messages`, `get_context`, `list_attachments`,
`get_attachment`, `get_image_preview`, `export_attachment`, and `read_pdf_attachment`.

Use `status` to check source freshness and coverage. The archive is a local
observation, not proof of complete phone history or an account-wide atomic
snapshot. Unsupported messages and unknown senders remain labeled.

Supported decoded images can be previewed inline. Only a thumbnail may be
available; WXGF/HEVC and animation remain unsupported. PDF text is paginated
and performs no OCR. Exports stay in the private state directory; they do not
modify the original attachment or upload it to another file service. Retrieved
content is nevertheless visible to the AI client, whose privacy policies apply.
See [attachment limits and behavior](docs/mcp.md#attachment-delivery).

## Development and provenance

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the pinned SQLCipher test build,
full test commands and synthetic-data rules. The 0.2.0 baseline has 630 tests.
Historical upstream review documents in `docs/` describe earlier revisions and
are not a new independent audit of this fork.

The upstream MIT license is retained in [LICENSE](LICENSE). The adapted capture
helper and external dependencies are credited in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Vulnerability reports follow
[SECURITY.md](../SECURITY.md).
