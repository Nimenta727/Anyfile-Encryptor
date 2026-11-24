# Anyfile-Encryptor / MOSAIC-ENC

Experimental authenticated file encryption. **Not independently audited; do not rely on either prototype for irreplaceable or highly sensitive information.**

## HDT v2 audit remediation candidate

64 KiB random keyfile (eight-axis shape), plus three NFC-normalized secret segments; Argon2id, HKDF-SHA256, AES-256-GCM-SIV, key commitment and authenticated header. See [protocol and security limits](docs/HDT_V2.md).

Python 3.10+; install official cryptography wheels:
```bash
python -m pip install --only-binary=cryptography -r requirements.txt
python -m core.hdt self-test
python -m core.hdt generate-key personal.mkey
python -m core.hdt encrypt input.txt input.hdt --keyfile personal.mkey
python -m core.hdt decrypt input.hdt recovered.txt --keyfile personal.mkey
python -m pytest -q
```
Secrets are prompted locally, not shell arguments. Use three strong independently generated random secrets; manual length checks are not entropy guarantees. Keep keyfile and secrets backed up separately; no recovery bypass. Do not lose any credential. This candidate requires a filesystem supporting hard links; it does not overwrite files. Not a desktop release.

## Legacy v0.1
Old MOSAIC01 files remain accessible via the unchanged CLI:
```bash
python mosaic.py encrypt input.txt input.mosaic
python mosaic.py decrypt input.mosaic recovered.txt
```
See [legacy design](docs/CRYPTO_DESIGN.md). Formats are not interchangeable; migrate by decrypting and re-encrypting to a new file after verifying recovery. No automatic fallback.
