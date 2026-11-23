"""MOSAIC-ENC v0.1 experimental authenticated file container.

Not independently audited. Requires the cryptography package.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

MAGIC = b"MOSAIC01"
CHUNK_SIZE = 1024 * 1024
MAX_HEADER = 4096
MAX_CHUNKS = 2**32 - 2
FINAL_MARKER = 0xFFFFFFFF
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class FormatError(ValueError):
    pass


def _exact(stream, n):
    data = stream.read(n)
    if len(data) != n:
        raise FormatError("Truncated encrypted file")
    return data


def _key(password, salt):
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )


def _chunk_key(master, index, final=False):
    purpose = b"final" if final else b"chunk"
    info = b"MOSAIC-ENC-v1|" + purpose + b"|" + struct.pack(">Q", index)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def _aad(header_digest, index, final=False):
    return b"MOSAIC-ENC-v1|" + header_digest + struct.pack(">Q", index) + (
        b"F" if final else b"D"
    )


def _header():
    salt = os.urandom(16)
    document = {
        "version": 1,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "chunk_size": CHUNK_SIZE,
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return salt, raw


def _parse_header(raw):
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or set(doc) != {
            "version", "cipher", "kdf", "n", "r", "p", "salt", "chunk_size"
        }:
            raise FormatError("Unexpected header fields")
        if (type(doc["version"]) is not int or doc["version"] != 1 or
            doc["cipher"] != "AES-256-GCM" or doc["kdf"] != "scrypt" or
            type(doc["n"]) is not int or doc["n"] != SCRYPT_N or
            type(doc["r"]) is not int or doc["r"] != SCRYPT_R or
            type(doc["p"]) is not int or doc["p"] != SCRYPT_P or
            type(doc["chunk_size"]) is not int or doc["chunk_size"] != CHUNK_SIZE):
            raise FormatError("Unsupported header parameters")
        salt = base64.b64decode(doc["salt"], validate=True)
        if len(salt) != 16:
            raise FormatError("Invalid salt")
        return salt
    except (KeyError, TypeError, ValueError) as exc:
        raise FormatError("Invalid header") from exc


def encrypt(source, destination, password):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must differ")
    salt, header = _header()
    master = _key(password, salt)
    digest = hashlib.sha256(MAGIC + struct.pack(">I", len(header)) + header).digest()
    with source.open("rb") as inp, destination.open("xb") as out:
        out.write(MAGIC + struct.pack(">I", len(header)) + header)
        index = 0
        while True:
            block = inp.read(CHUNK_SIZE)
            if not block:
                break
            if index >= MAX_CHUNKS:
                raise ValueError("Too many chunks")
            ciphertext = AESGCM(_chunk_key(master, index)).encrypt(
                b"\0" * 12, block, _aad(digest, index)
            )
            out.write(struct.pack(">I", len(ciphertext)))
            out.write(ciphertext)
            index += 1
        final = AESGCM(_chunk_key(master, index, True)).encrypt(
            b"\0" * 12, b"", _aad(digest, index, True)
        )
        out.write(struct.pack(">I", FINAL_MARKER) + final)


def decrypt(source, destination, password):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must differ")
    # Write to a private temporary file; publish only after the final tag verifies.
    temporary = None
    try:
        with source.open("rb") as inp:
            if _exact(inp, 8) != MAGIC:
                raise FormatError("Not a MOSAIC-ENC file")
            size = struct.unpack(">I", _exact(inp, 4))[0]
            if size == 0 or size > MAX_HEADER:
                raise FormatError("Invalid header size")
            raw = _exact(inp, size)
            salt = _parse_header(raw)
            master = _key(password, salt)
            digest = hashlib.sha256(MAGIC + struct.pack(">I", size) + raw).digest()
            fd, temporary = tempfile.mkstemp(prefix=".mosaic-", dir=destination.parent)
            with os.fdopen(fd, "wb") as out:
                index = 0
                while True:
                    length = struct.unpack(">I", _exact(inp, 4))[0]
                    if length == FINAL_MARKER:
                        tag = _exact(inp, 16)
                        AESGCM(_chunk_key(master, index, True)).decrypt(
                            b"\0" * 12, tag, _aad(digest, index, True)
                        )
                        if inp.read(1):
                            raise FormatError("Trailing bytes after final tag")
                        break
                    if index >= MAX_CHUNKS or length < 17 or length > CHUNK_SIZE + 16:
                        raise FormatError("Invalid chunk length")
                    data = _exact(inp, length)
                    plaintext = AESGCM(_chunk_key(master, index)).decrypt(
                        b"\0" * 12, data, _aad(digest, index)
                    )
                    if len(plaintext) != CHUNK_SIZE:
                        # Only the last data chunk may be short.
                        following = inp.peek(4)[:4] if hasattr(inp, "peek") else b""
                        if len(following) == 4 and struct.unpack(">I", following)[0] != FINAL_MARKER:
                            raise FormatError("Short non-final chunk")
                    out.write(plaintext)
                    index += 1
        if destination.exists():
            raise FileExistsError(destination)
        os.link(temporary, destination)
    except InvalidTag as exc:
        raise FormatError("Authentication failed: wrong password or modified file") from exc
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description="Experimental MOSAIC-ENC file encryption")
    parser.add_argument("action", choices=("encrypt", "decrypt"))
    parser.add_argument("source")
    parser.add_argument("destination")
    args = parser.parse_args()
    import getpass
    password = getpass.getpass("Password: ")
    try:
        if args.action == "encrypt":
            encrypt(args.source, args.destination, password)
        else:
            decrypt(args.source, args.destination, password)
        print("Completed.")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
