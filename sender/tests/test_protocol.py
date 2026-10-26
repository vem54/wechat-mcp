import pytest

from wechat_sender.protocol import text_message


@pytest.mark.parametrize("client_id", [0, -1, 2**32, 1 << 34, True, 1.5, "1"])
def test_current_client_id_rejects_non_uint32_values(client_id):
    with pytest.raises(ValueError, match="invalid_client_id"):
        text_message("filehelper", "test", timestamp=1, client_id=client_id)


def test_uint32_max_has_canonical_wire_encoding():
    encoded = text_message("filehelper", "test", timestamp=1, client_id=0xffffffff)
    # Field 5 tag (0x28), max uint32 varint, then field 6 bytes tag (0x32).
    assert b"\x28\xff\xff\xff\xff\x0f\x32" in encoded


def test_default_id_uses_nonzero_uint32(monkeypatch):
    bounds = []

    def choose(limit):
        bounds.append(limit)
        return limit - 1

    monkeypatch.setattr("wechat_sender.protocol.secrets.randbelow", choose)
    encoded = text_message("filehelper", "test", timestamp=1)
    assert bounds == [2**32 - 1]
    assert b"\x28\xff\xff\xff\xff\x0f\x32" in encoded
