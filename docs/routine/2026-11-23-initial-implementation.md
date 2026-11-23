# 2026-11-23 — Initial MOSAIC-ENC design and implementation

## Changes

- Established Python command-line encrypt/decrypt implementation for a new authenticated chunked file container.
- Added AES-256-GCM, scrypt password derivation, HKDF-SHA256 per-chunk key separation, header binding and authenticated final record.
- Added pytest coverage for round trips, wrong password, tampering, truncation, extra bytes, destination protection and random salts.
- Added design, threat model, security limitations and usage documentation.

## Verification status

Test suite is included but has **not yet been executed in a dependency-equipped runtime**. No security audit or formal cryptographic proof has been performed.

## Next steps

1. Install dependencies in CI and run pytest on Linux, macOS and Windows.
2. Add fuzz tests, cross-implementation known-answer vectors and crash-safe output cleanup.
3. Conduct independent review of file format, key schedule, memory usage and filesystem race conditions.
4. Consider an optional misuse-resistant AEAD and a separate post-quantum recipient-key wrapping format.
