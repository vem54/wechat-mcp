"""Inspect only signed application code; never infer compatibility from version alone."""
import hashlib
import json
from pathlib import Path
import plistlib
import struct


def arm64_slice(data: bytes) -> bytes:
    magic = struct.unpack_from(">I", data)[0]
    if magic == 0xCAFEBABE:
        count = struct.unpack_from(">I", data, 4)[0]
        for index in range(count):
            cputype, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
            if cputype == 0x0100000C:
                return data[offset:offset + size]
        raise ValueError("arm64_slice_missing")
    if magic == 0xCAFEBABF:
        count = struct.unpack_from(">I", data, 4)[0]
        for index in range(count):
            cputype, _, offset, size, _, _ = struct.unpack_from(">IIQQII", data, 8 + index * 32)
            if cputype == 0x0100000C:
                return data[offset:offset + size]
        raise ValueError("arm64_slice_missing")
    if struct.unpack_from("<II", data) != (0xFEEDFACF, 0x0100000C):
        raise ValueError("invalid_arm64_macho")
    return data


def code_sections(data: bytes) -> dict:
    """Section addresses are relative to the dylib image base (zero in WeChat)."""
    image = arm64_slice(data)
    ncmds, sizeofcmds = struct.unpack_from("<II", image, 16)
    if 32 + sizeofcmds > len(image):
        raise ValueError("invalid_macho_commands")
    offset = 32
    result = {}
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", image, offset)
        if size < 8 or offset + size > 32 + sizeofcmds:
            raise ValueError("invalid_macho_command")
        if cmd == 0x19:
            section_count = struct.unpack_from("<I", image, offset + 64)[0]
            for i in range(section_count):
                pos = offset + 72 + i * 80
                name, segment, address, length, file_offset = struct.unpack_from("<16s16sQQI", image, pos)
                key = segment.rstrip(b"\0").decode() + "," + name.rstrip(b"\0").decode()
                result[key] = {"address": address, "size": length, "offset": file_offset}
        offset += size
    return result


def inspect_app(app: Path) -> dict:
    with (app / "Contents/Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    data = arm64_slice((app / "Contents/Resources/wechat.dylib").read_bytes())
    section = code_sections(data)["__TEXT,__text"]
    code = data[section["offset"]:section["offset"] + section["size"]]
    return {"version": info["CFBundleShortVersionString"], "build": str(info["CFBundleVersion"]),
            "architecture": "arm64", "code_sha256": hashlib.sha256(code).hexdigest()}


def validate_profile(app: Path, profile: dict) -> dict:
    current = inspect_app(app)
    if any(current.get(key) != profile.get(key) for key in current):
        raise ValueError("profile_fingerprint_mismatch")
    data = arm64_slice((app / "Contents/Resources/wechat.dylib").read_bytes())
    section = code_sections(data)["__TEXT,__text"]
    required = {"taskCtor", "taskDtor", "startTask", "req2buf", "buf2resp",
                "onTaskEnd", "autoBufferWrite", "stringAssign"}
    if not required <= set(profile.get("offsets", {})):
        raise ValueError("profile_offsets_incomplete")
    sections = code_sections(data)
    for key in profile["offsets"]:
        address = int(profile["offsets"][key], 0)
        expected = bytes.fromhex(profile["expected_bytes"][key])
        if len(expected) < 16 or address % 4:
            raise ValueError("profile_signature_invalid")
        eligible = [s for name, s in sections.items() if name in {"__TEXT,__text", "__TEXT,__stubs"}
                    and s["address"] <= address and address + len(expected) <= s["address"] + s["size"]]
        if len(eligible) != 1:
            raise ValueError("profile_address_outside_code")
        section = eligible[0]
        delta = address - section["address"]
        start = section["offset"] + delta
        if data[start:start + len(expected)] != expected:
            raise ValueError("profile_signature_mismatch")
    return current


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, default=Path("/Applications/WeChat.app"))
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()
    info = inspect_app(args.app)
    if args.profile:
        validate_profile(args.app, json.loads(args.profile.read_text()))
        info["static_profile_valid"] = True
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
