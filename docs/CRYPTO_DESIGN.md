# MOSAIC-ENC v0.1 — Cryptographic Design

**Status:** experimental, unaudited. This is a new file container and key separation protocol, not a newly proven cipher.

## Threat model

Protect file contents from offline observers without the password. Detect corruption, chunk reordering, chunk substitution, truncation and trailing additions. Out of scope: weak passwords, endpoint compromise, filesystem rollback, side-channel attacks, hidden file sizes, and securely erasing plaintext.

## Container format

```text
MAGIC(8) | HEADER_LENGTH(u32 big endian) | HEADER(JSON UTF-8)
repeated: CIPHERTEXT_LENGTH(u32 BE) | AES-GCM ciphertext+tag
FINAL_MARKER(0xffffffff) | AES-GCM tag(16)
```

Header has canonical JSON on encryption, version 1, algorithm identifiers, scrypt settings, base64 salt and 1 MiB chunk size. Parser checks exact fields and fixed parameter values. Header maximum 4096 bytes.

## Key schedule

```text
master = scrypt(UTF8(password), salt16, N=32768, r=8, p=1, length=32)
K_i = HKDF-SHA256(master, info="MOSAIC-ENC-v1|chunk|" || uint64be(i), length=32)
K_final = HKDF-SHA256(master, info="MOSAIC-ENC-v1|final|" || uint64be(chunk_count), length=32)
H = SHA256(MAGIC || uint32be(header_length) || header)
AAD_i = "MOSAIC-ENC-v1|" || H || uint64be(i) || "D"
AAD_final = "MOSAIC-ENC-v1|" || H || uint64be(chunk_count) || "F"
```

AES-GCM nonce is 12 zero bytes for every invocation. This is safe **only under the assumption that each derived key is unique and used for one encryption operation**, which depends on HKDF separation and fresh random per-file salt. Never reuse the same salt and password to encrypt a second container. A future revision may adopt a misuse-resistant AEAD to reduce fragility.

Final record authenticates empty plaintext with a separate derived key and its own AAD. Decryptors reject missing final records and any trailing data.

## Security limitations

- A modified or incorrect password generally causes authentication failure, not plaintext disclosure.
- scrypt slows but does not eliminate offline password guessing.
- Authenticated encryption does not prevent replacing a whole file with a previously valid encrypted version (rollback).
- Output is staged in a private temporary file until the entire stream verifies; if a failure occurs, temporary output is removed. A crash can leave a temporary file, so disk encryption and cleanup are recommended.
- Filesystem race and symlink hardening, resource limits, interoperability vectors, and external cryptographic review are required before production use.
- This version is deliberately single-threaded and has no network or post-quantum key exchange.

## Test plan

Round trip empty/small/multi-chunk files, wrong passwords, header/body mutation, truncation, appended bytes, output overwrite prevention, and random salt uniqueness. Future: fuzzing, known-answer vectors, cross-platform CI, file permission checks, huge-file boundary tests, third-party review.

## References

- NIST SP 800-38D (AES-GCM): https://csrc.nist.gov/pubs/sp/800/38/d/final
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- RFC 7914 (scrypt): https://www.rfc-editor.org/rfc/rfc7914
