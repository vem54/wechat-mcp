# Licenses and provenance

This repository collects two components with separate licenses. The top-level
GPL text does not replace the MIT license in `reader/`.

| Path | License | Provenance |
| --- | --- | --- |
| `reader/` | MIT, except dependencies with their own notices | Based on xerlxzx/Wechat-MCP, revision `f6c99a6c25dedc08d47cbfb4044f22197547c81c`, upstream tag v0.1.2 lineage |
| `reader/src/wechat_bridge/setup/lldb_capture.py` | MIT | Adapted acmerfight capture helper; exact revision and retained license are in reader/THIRD_PARTY_NOTICES.md |
| `sender/` | GPL-3.0-only | Native interoperability/protocol research credited to yincongcyincong/wechat_chatter, reviewed revision `f222f37321f66d3a199cb3c7642f77f7504d85da` |
| Repository-level documentation, workflows and scripts | GPL-3.0-only | This fork's maintainers and contributors |

Upstream source:

- https://github.com/xerlxzx/Wechat-MCP
- https://github.com/yincongcyincong/wechat_chatter

Reader additions in this fork include private attachment export, bounded PDF text
extraction, image previews/crops and signal-aware background watching. Sender
additions include MCP tooling, durable request ledgers, account-bound recipient
resolution, native Mac-history integration, bounded lifecycle management and
non-sending reconciliation of late results. The new repository begins with a
clean source snapshot; the original projects remain credited and independently
available. Their contribution history is not represented as original work here.

The sender's software attribution remains in `sender/THIRD_PARTY_NOTICES.md`.
The GPL license document itself uses the unmodified standard text and its Free
Software Foundation copyright notice. That notice is for the license document,
not a claim that the FSF wrote this program.

Dependencies are obtained separately through the lockfiles and keep their own
licenses. See [reader notices](reader/THIRD_PARTY_NOTICES.md) and
[sender notices](sender/THIRD_PARTY_NOTICES.md). The authored C++ bridge's complete
source is included alongside its compiled library. Tencent's application and
proprietary database contents are not included.
