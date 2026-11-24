"""Real process/FS regression lab. Uses only synthetic fixtures in TemporaryDirectory."""
import contextlib
import errno
import multiprocessing as mp
import os
from pathlib import Path
import stat
import tempfile
import time
from core import hdt

PARTS = ("public-alpha-001", "public-beta-002", "public-gamma-003")
PAYLOAD = b"public-fixture" * 100000


def pause(ready):
    ready.set()
    while True:
        time.sleep(1)


def crash_worker(directory, point, ready):
    p = Path(directory)
    if point == "partial":
        original = hdt.atomic_output
        @contextlib.contextmanager
        def pause_after_write(dest):
            with original(dest) as out:
                class Writer:
                    def write(self, data):
                        out.write(data)
                        out.flush()
                        os.fsync(out.fileno())
                        pause(ready)
                yield Writer()
        hdt.atomic_output = pause_after_write
    else:
        original = hdt.os.link
        def paused_link(src, dst):
            if point == "after_link":
                original(src, dst)
            pause(ready)
        hdt.os.link = paused_link
    hdt.decrypt(p / "encrypted", p / "output", p / "key", PARTS)


def crash_case(ctx, p, point):
    ready = ctx.Event()
    child = ctx.Process(target=crash_worker, args=(str(p), point, ready))
    child.start()
    try:
        assert ready.wait(25), (point, child.exitcode)
        output = p / "output"
        assert output.exists() == (point == "after_link")
        child.kill()
        child.join(10)
        assert not child.is_alive() and child.exitcode != 0
        residuals = hdt.list_residuals(p)
        assert len(residuals) == 1, residuals
        temp = p / residuals[0]
        if os.name == "posix":
            assert stat.S_IMODE(temp.stat().st_mode) & 0o077 == 0
        if point == "partial":
            assert temp.stat().st_size == hdt.CHUNK
        else:
            assert temp.stat().st_size == len(PAYLOAD)
        if point == "after_link":
            assert output.read_bytes() == PAYLOAD and os.path.samefile(output, temp)
            output.unlink()
        else:
            assert not output.exists()
        assert hdt.list_residuals(p) == residuals
        temp.unlink()  # child joined, controlled synthetic directory
    finally:
        if child.is_alive():
            child.kill()
        child.join(10)


def contender(directory, index, barrier, result):
    path = Path(directory) / "shared"
    try:
        with hdt.atomic_output(path) as out:
            out.write(bytes([index]) * 65536)
            barrier.wait(20)
        result.put((index, "won"))
    except FileExistsError:
        result.put((index, "lost"))
    except BaseException as exc:
        result.put((index, repr(exc)))
        raise


def race(ctx, p, rounds=5, count=6):
    for _ in range(rounds):
        barrier, result = ctx.Barrier(count), ctx.Queue()
        procs = [ctx.Process(target=contender, args=(str(p), i, barrier, result)) for i in range(count)]
        for child in procs:
            child.start()
        try:
            outcomes = [result.get(timeout=30) for _ in procs]
            winners = [i for i, status in outcomes if status == "won"]
            assert len(winners) == 1 and sum(status == "lost" for _, status in outcomes) == count - 1, outcomes
            assert (p / "shared").read_bytes() == bytes(winners) * 65536
            assert not hdt.list_residuals(p)
            (p / "shared").unlink()
        finally:
            for child in procs:
                child.join(5)
                if child.is_alive():
                    child.kill()
                    child.join(5)
            result.close()
            result.join_thread()


def encryption_contender(directory, index, barrier, result):
    p = Path(directory)
    original = hdt.atomic_output
    @contextlib.contextmanager
    def synchronized(dest):
        with original(dest) as out:
            yield out
            barrier.wait(25)
    hdt.atomic_output = synchronized
    try:
        hdt.encrypt(p / f"source-{index}", p / "shared.hdt", p / "key", PARTS)
        result.put((index, "won"))
    except FileExistsError:
        result.put((index, "lost"))
    except BaseException as exc:
        result.put((index, repr(exc)))
        raise


def encryption_race(ctx, p):
    count = 4
    for i in range(count):
        (p / f"source-{i}").write_bytes(bytes([i]) * (hdt.CHUNK + 31))
    barrier, result = ctx.Barrier(count), ctx.Queue()
    procs = [ctx.Process(target=encryption_contender, args=(str(p), i, barrier, result)) for i in range(count)]
    for proc in procs:
        proc.start()
    try:
        outcomes = [result.get(timeout=40) for _ in procs]
        winners = [i for i, status in outcomes if status == "won"]
        assert len(winners) == 1 and sum(s == "lost" for _, s in outcomes) == count - 1, outcomes
        hdt.decrypt(p / "shared.hdt", p / "race-recovered", p / "key", PARTS)
        assert (p / "race-recovered").read_bytes() == (p / f"source-{winners[0]}").read_bytes()
        assert not hdt.list_residuals(p)
    finally:
        for proc in procs:
            proc.join(5)
            if proc.is_alive():
                proc.kill()
                proc.join(5)
        result.close()
        result.join_thread()


def limit_worker(directory):
    import resource
    import signal
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
    p = Path(directory)
    try:
        hdt.decrypt(p / "encrypted", p / "limited", p / "key", PARTS)
    except OSError as exc:
        assert exc.errno == errno.EFBIG, exc
    else:
        raise AssertionError("Expected kernel file size limit")
    assert not (p / "limited").exists() and not hdt.list_residuals(p)


def run(rounds=5, count=6):
    ctx = mp.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="hdt-public-lab-") as directory:
        p = Path(directory)
        (p / "plain").write_bytes(PAYLOAD)
        hdt.generate_keyfile(p / "key")
        hdt.encrypt(p / "plain", p / "encrypted", p / "key", PARTS)
        for point in ("partial", "before_link", "after_link"):
            crash_case(ctx, p, point)
            print("PASS kill", point, flush=True)
        race(ctx, p, rounds, count)
        print(f"PASS {rounds} rounds x {count} simultaneous publication contenders", flush=True)
        encryption_race(ctx, p)
        print("PASS 4 concurrent full encryptions, one valid winner", flush=True)
        if os.name == "posix":
            worker = ctx.Process(target=limit_worker, args=(directory,))
            worker.start()
            worker.join(30)
            if worker.is_alive():
                worker.kill()
                worker.join(5)
            assert worker.exitcode == 0, worker.exitcode
            print("PASS kernel RLIMIT_FSIZE/EFBIG", flush=True)
        hdt.decrypt(p / "encrypted", p / "recovered", p / "key", PARTS)
        assert (p / "recovered").read_bytes() == PAYLOAD == (p / "plain").read_bytes()
        print("PASS recovery after fault cases", flush=True)


if __name__ == "__main__":
    run()
