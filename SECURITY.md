# Security and privacy

This is experimental local software, not an audited or official WeChat API.
Do not post chat databases, account directories, keys, private profiles, images,
PDFs, logs, outbox rows or screenshots of personal conversations in public issues.

## Trust boundary

- The reader opens the user's local WeChat data and builds a separate private
  archive. State is owner-only but unencrypted at rest; another process running
  as the same OS user can access it.
- The MCP client sees the content it requests. This project cannot control that
  client's cloud retention or prevent an authorized client from exporting it.
- Retrieved messages and files are untrusted input. They never authorize a send,
  command execution or a change to account/security settings.
- The optional sender operates in a separately prepared app copy and uses a local
  private socket. Exact app fingerprints and account binding are required. It
  sends through WeChat's network connection, and records outgoing text locally.
- Timeouts and crashes can leave unknown outcomes. Reconcile the original request;
  never create a new request ID just to bypass uncertainty.
- Native compatibility depends on private implementation details and may break
  after updates. Shutdown waits for native work; hot unload is unsupported.
- PDF extraction runs in a resource-bounded child process, not an OS sandbox.
  It performs no OCR, JavaScript execution or external URL retrieval.

The default state directories are `~/Library/Application Support/WechatBridge`
and `~/Library/Application Support/WechatSender`. Keep these out of repositories,
public bug reports and shared/synced folders. The repository's ignore rules are
only an extra layer; they cannot protect files already committed or force-added.

## Reporting

Use the repository's **Security > Advisories > Report a vulnerability** channel
when available. If it is unavailable, open a minimal issue asking for a private
reporting channel without disclosing the vulnerability or personal data. Do not
invent a maintainer email or send secrets to an address found in source comments.

For ordinary bugs, report only the component version, OS/architecture, WeChat
version/build, a diagnostic code and synthetic reproduction steps. Review all
attachments yourself before sharing. CI tests require no real account or secrets.

This project has no relationship with Tencent. Users are responsible for having
permission to access the account and for evaluating service terms and applicable
rules in their environment. Open-source licensing is not Tencent approval.

## If private material leaks

Stop sharing it and remove the exposed material from public surfaces. Treat it as
already copied; deleting a commit does not undo exposure. Report through a private
channel. Database keys belong to WeChat and cannot be rotated by this project;
review the affected account and the scope of exposed chat data.
