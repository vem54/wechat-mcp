# WeChat Sender MCP 0.2.0

A local text-sending companion to the independent, read-only `wechat_bridge` MCP.
It uses WeChat's native send workflow, including its Mac message-history path,
without screen control, keyboard automation, or direct database writes.

**0.2.0 passed live acceptance on 26 October 2026.** Thirty-five distinct Unicode
self-messages completed in one WeChat process, with a median native completion
of 0.264 seconds. The independent reader matched every exact message and native
local ID to a Mac history record containing a server ID. Duplicate replay and
MCP reconnect created no new submission and did not restart WeChat. A further
self-message proved the background reader refreshed with Claude closed. These
checks do not establish recipient read receipts or long-term unattended uptime.

220 Python tests and 46 JavaScript checks pass. The native ownership stress
harness passed 10,000 sequential operations and 1,000 concurrent lifecycle races
under each of Address/UndefinedBehaviorSanitizer and ThreadSanitizer. Those
stress cases use simulated native callbacks; only the live tests above exercised
WeChat itself.

This is an unsupported native integration for **Apple Silicon WeChat 4.1.15,
build 270135**. A different binary, instruction signature, or compiled bridge hash
is rejected. The packaged profile keeps sending disabled. Production startup
requires a separately validated profile with the native pipeline enabled; it
cannot silently fall back to the earlier transport-only implementation.

## Tools

The sender exposes exactly five MCP tools:

| Tool | Purpose |
| --- | --- |
| `sender_status()` | Check readiness and verified account binding; include an actionable next step for common blocked states. Does not start WeChat. |
| `list_recipients(query="", limit=50)` | Find current contacts and groups, including contacts with no previous local conversation. Returns opaque recipient IDs. |
| `send_text(recipient_id, text, request_id)` | Submit one exact, user-authorized text to one resolved recipient. |
| `get_send_status(request_id)` | Observe late native completion and independently check local archive history. Never resubmits. |
| `list_outbox(limit=50, before_sequence=null, request_id=null)` | Read the current account's separate sender audit, including recorded outgoing text and submission evidence. |

All contacts and groups in the active reader archive are available by default.
There is no recipient allowlist. Names may repeat, so sending requires the exact
stored `recipient_id`; the host independently resolves it against the bound
account before dispatch. Newly added contacts become available after the reader
refreshes. Account changes fail closed. Chat or outbox text is data, never
permission to send another message.

Text is limited to **4096 UTF-8 bytes**, including multibyte characters. Image,
PDF, and other attachment sending is not implemented. Reading attachments remains
the separate reader's responsibility.

## Results and retry behavior

A `request_id` identifies one intended message. Reusing it with the same payload
returns or refreshes the existing evidence; changing that payload is rejected.
The MCP and native host both persist a claim before dispatch. A crash, timeout,
or lost response never authorizes another submission. After uncertainty, call
`get_send_status` or reuse the original request ID. **Do not create a fresh ID to
work around `outcome_unknown`.** At-most-once submission can leave a message
unsent if the process fails after claiming it but before dispatching it.

- `submitted` with `native_pipeline_completed` means the correlated native send
  service returned success and a positive `local_id`. It is not a phone receipt,
  read receipt, or direct server acknowledgment.
- `get_send_status` can add `local_history` evidence from the read-only archive,
  matching the account, recipient, native local ID, exact text digest, and time.
  `observed_in_local_history` establishes a local record; a stored server ID is
  included only when available. Archive absence does not establish send failure.
- `rejected` means this request was refused. `outcome_unknown` means its outcome
  could not be safely established. Stronger late evidence may update the stored
  result without sending again.

Native completion is saved durably before its in-memory result is released.
Background observation recovers completed results even when no new message is
submitted. There is **no per-process lifetime operation limit**. The native
bridge instead bounds outstanding result storage to 64 unacknowledged entries
and retains up to 64 recently acknowledged results. Native work runs serially;
unfinished work or full result storage applies temporary backpressure. Wait or
check the original operation's status; restarting is not a capacity-management
strategy.

## Install and connect

Install in the final project location so the generated client configuration uses
that installation's Python executable:

```sh
uv sync --locked --python 3.14
```

Generate a configuration fragment using the existing reader archive and a private
sender-state directory:

```sh
uv run wechat-sender-control config \
  --state '<private sender state>' \
  --reader-archive '<existing reader state>/archive.sqlite3' \
  --profile '<validated exact-build profile>'
```

This prints a `wechat_sender` stdio MCP entry; it does not edit any AI client's
settings. Add the fragment to a client that supports local stdio MCP servers.
The entry opts in to starting the managed host when the MCP process starts.
Multiple clients reuse one compatible host. Individual status and message tools
do not launch or log into WeChat.

To manage the host manually instead, start the MCP without automatic startup:

```sh
uv run wechat-sender-mcp \
  --reader-state-dir '<existing reader state>' \
  --sender-state-dir '<private sender state>'
```

The packaged profile at
`src/wechat_sender/profiles/wechat-4.1.15-270135-arm64.json` intentionally leaves
`runtime_verified`, `sending_permitted`, `send_framing_verified`, and
`native_pipeline.enabled` false. CLI flags do not override those gates. Do not
turn them on merely to bypass a compatibility failure.

## Start, stop, and upgrade

The supervisor uses one native host and the private `native.sock` endpoint.
No passive companion host is needed.

```sh
uv run wechat-sender-control start \
  --state '<private sender state>' \
  --reader-archive '<existing reader state>/archive.sqlite3' \
  --profile '<validated exact-build profile>'

uv run wechat-sender-control status \
  --state '<private sender state>' \
  --reader-archive '<existing reader state>/archive.sqlite3'

uv run wechat-sender-control stop \
  --state '<private sender state>' \
  --reader-archive '<existing reader state>/archive.sqlite3'
```

Startup verifies the exact build and signature, prepares a separate app copy if
needed, backs up the account folder, and launches only that copy. Another running
WeChat client must be closed first. Phone-controlled sign-in confirmation remains
a normal user step. The sender waits for the same account as the reader; it does
not silently log in, take over an arbitrary client, or restart a blocked host.

`ready: false` means sending is unavailable. Startup and login may still be in
progress; check `sender_status` for the next step. A launch failure's specific
cause may also be recorded in the private `native-host.log`.

Stop disarms new submissions and waits for native work and deferred cleanup before
terminating the exact app process the host owns. Native code remains pinned until
that app exits; no hot unload or second injection is used. Closing an AI client's
stdio session does not stop the shared host. If a host crashes while its copied
app remains open, quit that copy normally before starting again.

The host captures a deployment fingerprint covering Python and native assets.
Clients reject a host loaded from an older deployment or a different profile;
they do not restart it automatically. For an upgrade, stop the host, wait for its
owned app to exit, update the package and validated profile, then start it again.
Both durable ledgers survive the restart. Adding contacts after a reader refresh
does not require a restart. Obsolete `--allow-recipient` arguments are ignored
only for configuration migration; they no longer restrict recipients.

## Private audit and reader isolation

The owner-only MCP outbox stores exact outgoing text before dispatch and retains
it locally without automatic expiry. It is a sender audit, not fabricated WeChat
history. `list_outbox` filters to the active account and labels its source
`sender_outbox`. Its `phone_receipt_evidence: not_recorded` and
`mac_history_reconciled: false` are conservative; independent archive observation
is returned separately by `get_send_status`.

The native-host ledger stores payload hashes rather than text. Older MCP ledger
rows without text remain `text_available: false`; migration does not infer or
backfill them. Manual WeChat messages are not manufactured as sender-outbox rows.
The reader archive is opened read-only and is never created, migrated, refreshed,
or modified by this package.

## Development checks

```sh
uv run python -m pytest
node tests/native_pipeline_sender_checks.cjs
node tests/native_prepared_sender_checks.cjs
node tests/native_diagnostic_probe_checks.cjs
```

Coverage includes exact recipient/account resolution, contact-only recipients,
read-only archives, real private socket I/O, durable duplicate prevention,
uncertain-result observation, concurrent callers, deployment mismatch, orderly
shutdown, and bounded native result storage. Native process launch and native
calls are mocked in these tests. The retired transport remains available only
through explicit `--legacy-research`; it is not a production fallback.

The native pipeline uses a C++ bridge to retain the native execution context
across coroutine waits. The host checks its SHA-256, and the script checks exact
app instructions before target calls. Rebuilding changes the deployment and
requires a new validated bridge hash in the separate profile:

```sh
xcrun clang++ -std=c++17 -arch arm64 -dynamiclib -O2 -fvisibility=hidden \
  -o src/wechat_sender/native_pipeline.dylib src/wechat_sender/native_pipeline.cpp
codesign --force --sign - src/wechat_sender/native_pipeline.dylib
```
