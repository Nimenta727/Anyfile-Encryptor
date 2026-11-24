import ast
import hashlib
import hmac
from pathlib import Path
import pytest

from core import hdt

PARTS = ("test-alpha-001", "test-beta-002", "test-gamma-003")


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "test.mkey"
    hdt.generate_keyfile(p)
    return p


def test_primitive_and_encoding_kat():
    hdt.self_test()
    assert hdt.encode(b"alpha", b"beta", b"gamma").hex() == "00000005616c70686100000004626574610000000567616d6d61"
    assert hdt.password_key(("alpha", "beta", "gamma"), bytes(range(32))).hex() == "9e141886afbca41646532a1f52824f750750f1066af022467aa559dc817f4dcb"
    assert hdt.normalized(("café", "b", "c")) == hdt.normalized(("cafe\u0301", "b", "c"))
    assert hdt.normalized(("１", "b", "c")) != hdt.normalized(("1", "b", "c"))
    assert hdt.encode(b"a", b"bc") != hdt.encode(b"ab", b"c")


def test_keyfile(keyfile):
    assert keyfile.stat().st_size == 65603
    assert len(hdt.read_keyfile(keyfile)) == 65536
    raw = bytearray(keyfile.read_bytes())
    raw[35] ^= 1
    keyfile.write_bytes(raw)
    with pytest.raises(hdt.FormatError):
        hdt.read_keyfile(keyfile)


@pytest.mark.parametrize("size", [0, 1, hdt.CHUNK, hdt.CHUNK + 17])
def test_round_trip(tmp_path, keyfile, size):
    src, enc, dst = (tmp_path / n for n in ("src", "enc", "dst"))
    src.write_bytes(bytes(i % 251 for i in range(size)))
    hdt.encrypt(src, enc, keyfile, PARTS)
    assert enc.stat().st_size == size + 237 + 29 * ((size + hdt.CHUNK - 1) // hdt.CHUNK)
    hdt.decrypt(enc, dst, keyfile, PARTS)
    assert dst.read_bytes() == src.read_bytes()
    with pytest.raises(FileExistsError):
        hdt.decrypt(enc, dst, keyfile, PARTS)
    with pytest.raises(FileExistsError):
        hdt.encrypt(src, enc, keyfile, PARTS)


def test_four_credentials_and_domain_separation(tmp_path, keyfile):
    material = hdt.read_keyfile(keyfile)
    fid, sp, st = bytes(16), bytes(32), bytes([1]) * 32
    good = hdt.credential_keys(material, PARTS, fid, sp, st)
    assert good[0] != good[1]
    other = bytes([material[0] ^ 1]) + material[1:]
    changed = [(other, PARTS)]
    changed += [(material, tuple(v + "!" if j == i else v for j, v in enumerate(PARTS))) for i in range(3)]
    for m, p in changed:
        assert all(a != b for a, b in zip(good, hdt.credential_keys(m, p, fid, sp, st)))
    root = bytes([3]) * 32
    kh, kd, kf = hdt.data_keys(root, fid)
    assert len({kh, kd, kf, hdt.chunk_key(kd, fid, 0), hdt.chunk_key(kd, fid, 1)}) == 5
    src, enc, dst = (tmp_path / n for n in ("src", "enc", "dst"))
    src.write_bytes(b"test")
    hdt.encrypt(src, enc, keyfile, PARTS)
    wrong_key = tmp_path / "other.mkey"
    hdt.generate_keyfile(wrong_key)
    for k, p in [(wrong_key, PARTS)] + [(keyfile, p) for _, p in changed[1:]]:
        with pytest.raises(hdt.FormatError):
            hdt.decrypt(enc, dst, k, p)
        assert not dst.exists()


def test_malformed_records(tmp_path, keyfile):
    src, enc, dst = (tmp_path / n for n in ("src", "enc", "dst"))
    src.write_bytes(b"short test")
    hdt.encrypt(src, enc, keyfile, PARTS)
    original = enc.read_bytes()
    header_size = hdt.HEADER.size + 112
    mutations = [original[:-1], original + b"x", original[:header_size],
                 original[:header_size] + original[header_size:header_size + 1] + bytes(12) + original[header_size + 13:]]
    for i in (0, 12, 44, 92, 124, 172, header_size, header_size + 12, len(original) - 1):
        x = bytearray(original)
        x[i] ^= 1
        mutations.append(bytes(x))
    for data in mutations:
        enc.write_bytes(data)
        with pytest.raises(hdt.FormatError):
            hdt.decrypt(enc, dst, keyfile, PARTS)
        assert not dst.exists()
        assert not list(tmp_path.glob(".mosaic-hdt-*.tmp"))


def test_splice_and_reorder(tmp_path, keyfile):
    src, a, b, dst = (tmp_path / n for n in ("src", "a", "b", "dst"))
    src.write_bytes(b"x" * (2 * hdt.CHUNK))
    hdt.encrypt(src, a, keyfile, PARTS)
    hdt.encrypt(src, b, keyfile, PARTS)
    raw, other = a.read_bytes(), b.read_bytes()
    h = hdt.HEADER.size + 112
    n = hdt.CHUNK + 29
    for bad in (raw[:h] + other[h:h+n] + raw[h+n:],
                raw[:h] + raw[h+n:h+2*n] + raw[h:h+n] + raw[h+2*n:],
                raw[:h] + raw[h:h+n] + raw[h:h+n] + raw[h+2*n:],
                raw[:h] + raw[h+n:]):
        a.write_bytes(bad)
        with pytest.raises(hdt.FormatError):
            hdt.decrypt(a, dst, keyfile, PARTS)
        assert not dst.exists()


def test_nfc_round_trip(tmp_path, keyfile):
    src, enc, dst = (tmp_path / n for n in ("src", "enc", "dst"))
    src.write_bytes(b"unicode")
    hdt.encrypt(src, enc, keyfile, ("café-secret", PARTS[1], PARTS[2]))
    hdt.decrypt(enc, dst, keyfile, ("cafe\u0301-secret", PARTS[1], PARTS[2]))
    assert dst.read_bytes() == b"unicode"


def test_research_import_boundary():
    for p in (Path(__file__).resolve().parents[1] / "core").rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                assert all("research" not in alias.name.split(".") for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert "research" not in (node.module or "").split(".")
                assert all(alias.name != "research" for alias in node.names)
