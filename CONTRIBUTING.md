# Contributing

Work in a separate checkout, never in an installation attached to a running
native host. Contributions retain the license of the component they modify:
MIT for `reader/`, GPL-3.0-only for `sender/` and repository-level additions.
Preserve upstream copyright and third-party notices.

## Test setup

Use Python 3.14, uv, Node 22+, Apple Command Line Tools and SQLCipher 4 on macOS.
The reader integration fixtures expect the pinned SQLCipher build below; this
also gives CI a known FTS5-enabled native dependency.

```sh
brew install uv openssl@3
cd reader
uv sync --locked
uv run python scripts/build_sqlcipher.py --openssl-prefix "$(brew --prefix openssl@3)"
uv run pytest -q
uv build
cd ../sender
uv sync --locked --python 3.14
uv run pytest -q
uv build
node tests/native_pipeline_sender_checks.cjs
node tests/native_prepared_sender_checks.cjs
node tests/native_diagnostic_probe_checks.cjs
```

The fixtures are synthetic. Tests do not require WeChat, access a live account,
launch a real sender or send messages. Do not add real captures as fixtures.

## Native lifecycle harness

Run from `sender/` on macOS. Each harness uses mocked native callbacks:

```sh
mkdir -p .build
clang++ -std=c++17 -pthread -O1 -g -fsanitize=address,undefined \
  tests/native_pipeline_lifecycle.cpp -o .build/lifecycle-asan
.build/lifecycle-asan
clang++ -std=c++17 -pthread -O1 -g -fsanitize=thread \
  tests/native_pipeline_lifecycle.cpp -o .build/lifecycle-tsan
.build/lifecycle-tsan
```

A passing harness is not proof that new offsets or an ABI work in WeChat. Any new
build profile needs separate static review and controlled runtime validation.
Never turn on a profile flag to make a test pass. Preserve durable duplicate
protection, account binding, cleanup ordering and independent history evidence.

## Pull requests and reports

Explain the user-visible behavior and the tests run. Keep generated state and
personal information out of diffs, commit history, screenshots and CI artifacts.
Run `python3 scripts/check_public_tree.py` at the repository root before commit.
A full secret scan is still required before releases. Security reports follow
[SECURITY.md](SECURITY.md).

## GitHub Actions

The inactive workflow is [docs/ci-template.yml](docs/ci-template.yml). To enable
it, copy it to `.github/workflows/ci.yml` and commit/push using a credential
with permission to write workflows. It requires no WeChat account or secrets.
The public preview was tested locally; it does not claim a GitHub Actions run.
