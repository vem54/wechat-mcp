"""Text wire schema adapted from wechat_chatter's GPLv3 text_msg.proto.

This only encodes a message; it has no network, database, or UI effects.
"""
import secrets
import time


def varint(value: int) -> bytes:
    if not 0 <= value < 2**64:
        raise ValueError("invalid_integer")
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def integer(field: int, value: int) -> bytes:
    return varint(field << 3) + varint(value)


def blob(field: int, value: bytes) -> bytes:
    return varint((field << 3) | 2) + varint(len(value)) + value


def text_message(recipient: str, content: str, *, timestamp: int | None = None,
                 client_id: int | None = None) -> bytes:
    if not recipient or len(recipient.encode()) > 512 or "\0" in recipient:
        raise ValueError("invalid_recipient")
    payload = content.encode("utf-8")
    if not content.strip() or len(payload) > 4096 or "\0" in content:
        raise ValueError("invalid_text")
    timestamp = int(time.time()) if timestamp is None else timestamp
    # Current 4.1.15 item field 5 is uint32. The older research project's
    # 35-bit generator is incompatible with this version's native serializer.
    client_id = secrets.randbelow(2**32 - 1) + 1 if client_id is None else client_id
    if type(client_id) is not int or not 0 < client_id < 2**32:
        raise ValueError("invalid_client_id")
    body = (blob(1, blob(1, recipient.encode())) + blob(2, payload) + integer(3, 1)
            + integer(4, timestamp) + integer(5, client_id)
            + blob(6, b"<msgsource><alnode><fr>1</fr></alnode></msgsource>"))
    return integer(1, 1) + blob(2, body)
