# Laboratory report — 2026-11-24
Public synthetic fixtures only. Local Linux container, Xeon Platinum 8370C, CPU quota 4 cores, cgroup memory 4 GiB; Python cryptography 46.0.4, argon2-cffi 25.1.0; native OpenSSL 3.5.5 and libargon2. No real user credentials.

## Argon2id experiment
3 runs per suite in separate processes; t=3, p=4, version=19, output=32 bytes. Median and peak RSS of process (Linux KiB):
| Suite | m KiB | seconds (3) | median s | peak RSS KiB |
|---|---:|---|---:|---:|
| 1 | 65536 | .112/.095/.070 | .095 | 161488 |
| 2 | 262144 | .303/.327/.309 | .309 | 358100 |
| 3 | 524288 | .841/.848/.627 | .841 | 620176 |
| 4 | 1048576 | 1.541/1.197/1.115 | 1.197 | 1144524 |
These results are latency, not attacker throughput or security bits; only one machine and three trials. Memory budget limits KDF allocation not entire process RSS. Parallel KDF requests still multiply memory; desktop must serialize operations.

## Cross-language KAT
Native C generator compiled and executed; all four 269-byte containers reproduced byte-for-byte using separate Python protocol reconstruction, including header commitment, W, M, record and encrypted final. Python reconstruction also authenticated the data record. Both use libargon2/OpenSSL-family implementations; this validates independent serialization/key schedule code, not independent primitive implementation. Full actual Core encrypt/decrypt regression added for CI; not reported locally until run. Public fixed test randomness never used by production CLI.
SHA-256:
1 bd0aa3adc330a17ebf9a3339b9606a27722b3ddb5e950c0215b127df0d6eed6f
2 fa432f95257ccf7f9f6c1fff8ea4fa3de7eaee22deb81f0a16a46f60812e80b6
3 e52d9d1a852180770adddd03af431882e5fd540cf1bd46cc93ffa6d1fd30595c
4 395be22dd9ab6692633c6c7c65c1818735825c81cd95392846eccd3c56115460
For C regeneration on Linux with OpenSSL >=3.2 and libargon2 installed: cc -O2 verification/vector.c -o /tmp/hdt-vector -lcrypto -l:libargon2.so.1 ; /tmp/hdt-vector 1 | xxd -p -c 269 . Repeat for IDs 2–4. Compare to verification/vectors/suiteN.hex. Use a platform-appropriate linker flag for libargon2. Run python verification/stream_model.py and python verification/bench_argon2.py 65536 (etc.).

## Operational hardening
Candidate protected Windows DACL at creation (current user + SYSTEM), no permissive fallback; final hard link shares that DACL. Windows CI assertion verifies protected DACL flag, not full access-control adversarial testing. POSIX private temp; trust destination directory, volume and process identity. List crash candidates without deleting any; close all instances and manually inspect before cleanup. No secure erasure guarantee. Early memory cap before KDF; default CLI encrypt suite 2, decrypt cap 256 MiB. Dropping Python references shortens retention only; native and interpreter copies not guaranteed wiped. Version constraints include cryptography 50.0.2 (official changelog 2026-09-30), pinned runtime dependencies, no artifact hashes; full per-platform hash locks and advisory review remain release blockers. Local bench used an older library and is not evidence of security-patched distribution.

## Independent review packet
Review docs/HDT_V2.md, docs/SECURITY_ARGUMENT.md, core/hdt.py, core/windows_private.py, tests/test_hdt.py and tests/test_hdt_lab.py together. Ask reviewer to attack the specification and implementation and reproduce KATs; supply only public synthetic vectors. No assertion that reviewer has actually reviewed or approved.
