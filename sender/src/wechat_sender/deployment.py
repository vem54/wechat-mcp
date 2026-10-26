"""Capture the implementation loaded by this process, independently of app profile."""
import hashlib
from pathlib import Path


def fingerprint(package: Path) -> str:
    digest = hashlib.sha256(b"wechat-sender-deployment-v1\0")
    for path in sorted(package.iterdir()):
        if path.is_file() and path.suffix in {".py", ".js", ".cpp", ".dylib"}:
            name, content = path.name.encode(), path.read_bytes()
            digest.update(len(name).to_bytes(4, "big") + name)
            digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


# Import-time capture is intentional: replacing installed files must not make a
# running host report the fingerprint of code it has never loaded.
DEPLOYMENT_FINGERPRINT = fingerprint(Path(__file__).parent)
