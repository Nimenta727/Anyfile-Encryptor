"""Cross-language fixtures and hardening regressions."""
import hashlib
import os
from pathlib import Path
import struct
import pytest
from core import hdt
from verification.stream_model import check

PARTS = ("test-alpha-001", "test-beta-002", "test-gamma-003")
VECTORS = Path(__file__).resolve().parents[1] / "verification" / "vectors"


def fixture_key(path):
    material = bytes(i % 251 for i in range(65536))
    raw = b"MOSKEY02" + struct.pack(">H", 2) + bytes([8] + [4] * 8) + bytes(16) + material
    path.write_bytes(raw + hashlib.sha256(raw).digest())


@pytest.mark.parametrize("suite", [1, 2, 3, 4])
def test_native_c_fixture(suite, tmp_path, monkeypatch):
    key, src, enc, out = (tmp_path / x for x in ("test.mkey", "plain", "encrypted", "restored"))
    fixture_key(key)
    src.write_bytes(b"abc")
    fixture = bytes.fromhex((VECTORS / f"suite{suite}.hex").read_text())
    assert len(fixture) == 269
    values = iter([bytes(range(96, 112)), bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))])
    def deterministic_test_random(n):
        result = next(values)
        assert len(result) == n
        return result
    monkeypatch.setattr(hdt, "_random_bytes", deterministic_test_random)
    hdt.encrypt(src, enc, key, PARTS, suite=suite)
    assert enc.read_bytes() == fixture
    hdt.decrypt(enc, out, key, PARTS, max_memory_mib=1024)
    assert out.read_bytes() == b"abc"


@pytest.mark.parametrize("suite", [3, 4, 65535])
def test_reject_before_kdf(suite, tmp_path, monkeypatch):
    src, dst = tmp_path / "header", tmp_path / "out"
    src.write_bytes(hdt.HEADER.pack(hdt.MAGIC, 2, suite, bytes(16), bytes(32), bytes(32)))
    def forbidden(*args, **kwargs):
        pytest.fail("KDF executed before suite and budget checks")
    monkeypatch.setattr(hdt, "credential_keys", forbidden)
    with pytest.raises(hdt.FormatError):
        hdt.decrypt(src, dst, tmp_path / "nonexistent", PARTS)
    assert not dst.exists()


def test_residuals_report_only(tmp_path):
    residual = tmp_path / ".mosaic-hdt-example.tmp"
    residual.write_bytes(b"test data")
    (tmp_path / "unrelated.tmp").write_bytes(b"x")
    (tmp_path / ".mosaic-hdt-folder.tmp").mkdir()
    assert hdt.list_residuals(tmp_path) == [residual.name]
    assert residual.read_bytes() == b"test data"


def test_failure_removes_temp_and_preserves_existing(tmp_path):
    out = tmp_path / "output"
    with pytest.raises(RuntimeError):
        with hdt.atomic_output(out) as f:
            f.write(b"test data")
            raise RuntimeError("simulated application failure")
    assert not out.exists()
    assert not hdt.list_residuals(tmp_path)
    out.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        with hdt.atomic_output(out):
            pytest.fail("overwrote existing output")
    assert out.read_bytes() == b"existing"


def test_bounded_stream_model():
    assert check() == 78185


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL only")
def test_windows_protected_dacl(tmp_path):
    import ctypes as C
    from ctypes import wintypes as W
    adv = C.WinDLL("advapi32", use_last_error=True)
    get = adv.GetFileSecurityW
    get.argtypes = (W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD))
    get.restype = W.BOOL
    ctl = adv.GetSecurityDescriptorControl
    ctl.argtypes = (C.c_void_p, C.POINTER(W.WORD), C.POINTER(W.DWORD))
    ctl.restype = W.BOOL
    path = tmp_path / "private"
    with hdt.atomic_output(path) as f:
        f.write(b"test")
    needed = W.DWORD()
    get(str(path), 4, None, 0, C.byref(needed))
    assert needed.value
    buf = C.create_string_buffer(needed.value)
    assert get(str(path), 4, buf, needed, C.byref(needed))
    control, revision = W.WORD(), W.DWORD()
    assert ctl(buf, C.byref(control), C.byref(revision))
    assert control.value & 0x1000  # SE_DACL_PROTECTED
    assert path.read_bytes() == b"test"
