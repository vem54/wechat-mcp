# Building the authored native bridge

The checked-in `sender/src/wechat_sender/native_pipeline.dylib` is an ad-hoc-signed
Apple Silicon build of `native_pipeline.cpp`, authored for this integration. It
contains no copied Tencent executable or account data. The public profile stores
its SHA-256 and keeps sending disabled.

To compile a separate comparison build without replacing the packaged library:

```sh
cd sender
mkdir -p .build
xcrun clang++ -std=c++17 -arch arm64 -dynamiclib -O2 -Wall -Wextra -Werror \
  -fvisibility=hidden -o .build/native_pipeline.dylib src/wechat_sender/native_pipeline.cpp
codesign --force --sign - .build/native_pipeline.dylib
codesign --verify --strict .build/native_pipeline.dylib
shasum -a 256 .build/native_pipeline.dylib
```

Compiler/SDK versions, Mach-O identity and signing can change the output hash;
byte-for-byte reproducibility is not claimed. The reference binary used Apple
Clang 21 on macOS 26.6.2. If replacing it, update the reviewed profile's library
hash as part of a deliberate deployment, then validate the ABI and native path.
A hash alone is not validation. Never replace the library while the native host
or its owned WeChat process is running.

The complete source and synthetic lifecycle harness are in this repository.
See [CONTRIBUTING.md](../CONTRIBUTING.md) for sanitizer commands. Native app offsets
and instruction signatures in the public profile describe WeChat 4.1.15 build
270135 only. They are not account keys or a portable API.
