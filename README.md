# Anyfile-Encryptor / MOSAIC-ENC

Experimental, versioned authenticated file encryption format. **Not independently audited; do not rely on this prototype for irreplaceable or highly sensitive information.**

## Design

- AES-256-GCM authenticated encryption via the audited `cryptography` package
- scrypt password derivation (N=32768, r=8, p=1), 16-byte random salt
- HKDF-SHA256 derives a distinct key for every 1 MiB chunk
- Each chunk uses its unique key once with the fixed 96-bit GCM nonce; **never reuse a derived key**
- SHA-256 header digest bound into every chunk's associated authenticated data
- An authenticated final marker binds chunk count and detects truncation or appended data
- Decryption writes to a temporary file and publishes only after verification
- Existing destinations are never overwritten

## Install

Python 3.10+:

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python mosaic.py encrypt input.txt input.mosaic
python mosaic.py decrypt input.mosaic recovered.txt
python -m pytest -q
```

Passwords are prompted interactively, not passed as shell arguments.

## Security scope

This is an **original container/protocol composition**, not a new mathematically validated block cipher. The project does not provide rollback protection, metadata confidentiality (such as filenames in filesystem), secure deletion, password recovery, or protection against compromised endpoints. The format is not yet independently reviewed. Password strength matters. File format and KDF settings are intentionally fixed for v1 to prevent unbounded memory consumption from untrusted headers.

See [design](docs/CRYPTO_DESIGN.md) and [routine log](docs/routine/2026-11-23-initial-implementation.md).
