import os
import struct
import pytest
from mosaic import encrypt, decrypt, FormatError


@pytest.mark.parametrize("payload", [b"", b"hello", os.urandom(1024 * 1024 + 19)])
def test_round_trip(tmp_path, payload):
    src, enc, dst = (tmp_path / name for name in ("plain", "cipher", "restored"))
    src.write_bytes(payload)
    encrypt(src, enc, "test password")
    decrypt(enc, dst, "test password")
    assert dst.read_bytes() == payload


def test_wrong_password(tmp_path):
    src, enc, dst = (tmp_path / name for name in ("plain", "cipher", "restored"))
    src.write_bytes(b"secret")
    encrypt(src, enc, "correct")
    with pytest.raises(FormatError):
        decrypt(enc, dst, "incorrect")
    assert not dst.exists()


@pytest.mark.parametrize("mutation", ["header", "body", "truncate", "append"])
def test_tampering(tmp_path, mutation):
    src, enc, dst = (tmp_path / name for name in ("plain", "cipher", "restored"))
    src.write_bytes(b"data" * 100)
    encrypt(src, enc, "password")
    data = bytearray(enc.read_bytes())
    if mutation == "header":
        data[20] ^= 1
    elif mutation == "body":
        data[-25] ^= 1
    elif mutation == "truncate":
        data = data[:-1]
    else:
        data.extend(b"extra")
    enc.write_bytes(data)
    with pytest.raises(FormatError):
        decrypt(enc, dst, "password")
    assert not dst.exists()


def test_output_not_overwritten(tmp_path):
    src, enc, dst = (tmp_path / name for name in ("plain", "cipher", "restored"))
    src.write_bytes(b"hello")
    encrypt(src, enc, "password")
    dst.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        decrypt(enc, dst, "password")
    assert dst.read_bytes() == b"existing"


def test_distinct_salts(tmp_path):
    src = tmp_path / "plain"
    src.write_bytes(b"identical")
    encrypt(src, tmp_path / "a", "password")
    encrypt(src, tmp_path / "b", "password")
    assert (tmp_path / "a").read_bytes() != (tmp_path / "b").read_bytes()
