# WeChat MCP for macOS

Read locally available WeChat chats and attachments through MCP, with an optional
native text sender. No screen control, mouse clicks or keyboard automation.

**Experimental and unofficial.** The reader has setup instructions; the sender
is a reference implementation that still requires manual, exact-build validation.
It is not a universal or one-click WeChat API. Tencent does not endorse this project.

## What works

| Component | Capabilities | Boundary |
| --- | --- | --- |
| Reader | Search contacts and chats; chronological messages, replies and group metadata | Only history present on this Mac; coverage is reported |
| Attachments | Local file export, paginated PDF text, supported image previews and crops | Missing files, unsupported formats and thumbnails stay explicitly labeled |
| Background sync | Refresh the private archive while WeChat receives messages | Mac awake, matching account logged in; no automatic business summaries |
| Sender | Text through WeChat's native send workflow, including Mac history | Apple Silicon, WeChat 4.1.15 build 270135; validated private profile required |
| Send tracking | Durable request IDs, duplicate prevention and late-result observation | Uncertain sends are never automatically repeated; no read-receipt claim |

The reader exposes **12 tools**, the sender **5**. All contacts and groups in the
active archive are eligible; there is no contact allowlist. Sending requires a
user instruction, an exact resolved recipient and a stable request ID.

## Compatibility and limits

- Local macOS on Apple Silicon. This fork was exercised on macOS 26.6.2.
- Reader schema checks accept WeChat 4.1.15 builds 270102 and 270135; this fork's
  live acceptance used 270135. Sender support is **270135 only**.
- Python 3.14, `uv`, SQLCipher 4, and Apple Command Line Tools for setup.
- Text sending: at most **4096 UTF-8 bytes**. Sending images/PDFs is not implemented.
- File export: **200 MiB**; image decode: **50 MiB / 40 million pixels**; inline
  previews: **1 MiB**. These are per-file/resource limits, not lifetime quotas.
- PDF text is paginated, with no OCR. WXGF/HEVC and animated images are unsupported;
  a readable thumbnail does not prove the original can be decoded. Voice/video
  content and some message types are not readable by this implementation.
- A WeChat update can invalidate native compatibility. The sender refuses a
  mismatched binary or deployment instead of silently trying it.

## Start with the reader

```sh
git clone https://github.com/vem54/wechat-mcp.git
cd wechat-mcp/reader
brew install uv sqlcipher
uv sync --locked
uv run wechat-bridge doctor
uv run wechat-bridge discover
```

Then follow [reader setup](reader/docs/setup.md) to verify/capture your own database
keys and create the first archive. Key capture is a separate explicit operation:
it uses a locally signed copy of WeChat under a debugger and may require phone
sign-in confirmation. It does not modify `/Applications/WeChat.app`, require
`sudo`, or disable macOS protections. Never run setup again for ordinary queries.

Once the archive is ready:

```sh
uv run wechat-bridge serve
```

Configure a **local stdio MCP client** to run the absolute path to
`reader/.venv/bin/wechat-bridge` with arguments `serve`. The default private state
is `~/Library/Application Support/WechatBridge`. Detailed schemas, explicit state
paths and client registration examples are in [the MCP reference](reader/docs/mcp.md).
Claude Desktop was tested. Other clients must support local stdio MCP; this repo
does not expose a remote connector for hosted ChatGPT or Grok.

## Optional sender

Read [sender setup and result semantics](sender/README.md) before installing it.

```sh
cd ../sender
uv sync --locked --python 3.14
```

The included native bridge is built from the C++ source in this repository; it
is **not** a Tencent binary. Its hash is verified before loading. A local rebuild
is documented in [native build instructions](docs/native-build.md).

The shipped app profile deliberately keeps sending disabled. A fresh installation
needs its own reviewed exact-build profile, verified account binding and controlled
self-test. Merely changing the enable flags is not validation. Automated sender
onboarding is not included. The working local acceptance run used a separate
private profile which is not published.

Normal operation reuses one owned WeChat process. There is no 32-send lifetime
ceiling. New native code requires a deliberate stop, complete app exit and restart;
ordinary sends and client reconnects do not restart the app. An app restart can
require phone sign-in confirmation.

## Privacy and trust

Keys, archives, exported files and sender journals belong outside the checkout.
They contain private data and must never be attached to issues or committed.
The reader does not upload the archive itself, but any content requested through
MCP is visible to the connected AI client and subject to that client's policies.
The sender uses WeChat's normal network connection to send authorized messages.

Messages and attachments are untrusted content, not instructions for an agent.
See [SECURITY.md](SECURITY.md) for the trust boundary and reporting instructions.

## Development and evidence

```sh
cd reader
uv sync --locked
uv run pytest -q
cd ../sender
uv sync --locked --python 3.14
uv run pytest -q
node tests/native_pipeline_sender_checks.cjs
node tests/native_prepared_sender_checks.cjs
node tests/native_diagnostic_probe_checks.cjs
```

Reader integration tests use an external SQLCipher library; see
[CONTRIBUTING.md](CONTRIBUTING.md) for its pinned build and the native sanitizer
harness. Tests use synthetic accounts and do not need WeChat or send messages.

The [CI template](docs/ci-template.yml) contains the test/build workflow but is
not active in this repository. Installing it under `.github/workflows/` requires
a GitHub credential with workflow-write permission. Local test results below
were verified before publication.

The 0.2.0 baseline passed 630 reader tests, 220 sender tests and 46 JavaScript
checks. One Mac completed a 35-message Unicode self-test with median native
completion of 0.264 seconds; all messages were independently found in its local
history with server IDs. Duplicate replay and client reconnect made no new send.
This is a local observation, not a speed guarantee, device receipt, security audit
or evidence of long-term unattended uptime. No private test records are included.

## License and provenance

- `reader/`: **MIT**, derived from [xerlxzx/Wechat-MCP](https://github.com/xerlxzx/Wechat-MCP).
- `sender/`: **GPL-3.0-only**, with attribution to
  [yincongcyincong/wechat_chatter](https://github.com/yincongcyincong/wechat_chatter).
- Repository-level additions: **GPL-3.0-only**.

The components retain separate licenses. See [LICENSES.md](LICENSES.md) for
provenance, upstream revision IDs and dependency notices. No Tencent application,
chat history, account keys or private runtime configuration is redistributed.
