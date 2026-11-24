"""Run one suite per process to isolate peak RSS (Linux KiB)."""
import sys
import time
import resource
import statistics
from argon2.low_level import hash_secret_raw, Type

m = int(sys.argv[1])
if m not in (65536, 262144, 524288, 1048576):
    raise SystemExit("Unsupported benchmark memory")
times = []
for _ in range(3):
    t = time.perf_counter()
    out = hash_secret_raw(b"PUBLIC-TEST-ONLY", bytes(range(32)), 3, m, 4, 32, Type.ID, 19)
    times.append(time.perf_counter() - t)
print(m, [round(x, 3) for x in times], round(statistics.median(times), 3),
      resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, out.hex(), flush=True)
