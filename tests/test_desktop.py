from pathlib import Path
from desktop.jobs import run
from core import hdt

PARTS = ("public-alpha-001", "public-beta-002", "public-gamma-003")


def test_round_trip_and_no_overwrite(tmp_path):
    s, c, k, out = (tmp_path / n for n in ("原始.bin", "file.hdt", "file.mkey", "restored.bin"))
    s.write_bytes(b"public fixture" * 90000)
    assert run("encrypt", str(s), str(c), str(k), PARTS, PARTS, 1).status == "ok"
    assert k.stat().st_size == hdt.KEY_SIZE
    assert run("decrypt", str(c), str(out), str(k), PARTS, (), 64).status == "ok"
    assert out.read_bytes() == s.read_bytes()
    assert run("decrypt", str(c), str(out), str(k), PARTS, (), 64).status == "error"
    assert run("encrypt", str(s), str(c), str(k), PARTS, PARTS, 1).status == "error"
    assert out.read_bytes() == s.read_bytes()


def test_bad_confirmation_and_wrong_parameter(tmp_path):
    s, c, k, out = (tmp_path / n for n in ("source", "cipher", "key", "out"))
    s.write_bytes(b"fixture")
    wrong = (*PARTS[:2], "public-other-003")
    assert run("encrypt", str(s), str(c), str(k), PARTS, wrong, 1).status == "error"
    assert not k.exists() and not c.exists()
    assert run("encrypt", str(s), str(c), str(k), PARTS, PARTS, 1).status == "ok"
    assert run("decrypt", str(c), str(out), str(k), wrong, (), 64).status == "error"
    assert not out.exists()


def test_key_retained_on_encryption_failure(tmp_path, monkeypatch):
    s, c, k = (tmp_path / n for n in ("source", "cipher", "key"))
    s.write_bytes(b"fixture")
    def fail(*args, **kwargs):
        raise OSError("synthetic write failure")
    monkeypatch.setattr(hdt, "encrypt", fail)
    r = run("encrypt", str(s), str(c), str(k), PARTS, PARTS, 1)
    assert r.status == "error" and str(k) in r.message
    assert k.stat().st_size == hdt.KEY_SIZE and not c.exists()


def test_same_paths_rejected(tmp_path):
    s, c = tmp_path / "source", tmp_path / "cipher"
    s.write_bytes(b"fixture")
    assert run("encrypt", str(s), str(c), str(c), PARTS, PARTS, 1).status == "error"
    assert not c.exists()
