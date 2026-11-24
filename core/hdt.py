"""MOSAIC-HDT v2 candidate. Experimental; no independent implementation audit."""
import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import stat
import struct
import tempfile
import unicodedata
import warnings
from contextlib import contextmanager
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

MAGIC = b"MOSHDT02"
KEY_MAGIC = b"MOSKEY02"
SHAPE = bytes([8] + [4] * 8)
KEY_BYTES = 4**8
KEY_SIZE = 8 + 2 + 9 + 16 + KEY_BYTES + 32
HEADER = struct.Struct(">8sHH16s32s32s")
RECORD = struct.Struct(">BQI")
COUNTS = struct.Struct(">QQ")
VERSION, SUITE = 2, 1
# Protocol IDs are immutable; values are KiB, not MB.
SUITES = {1: 65536, 2: 262144, 3: 524288, 4: 1048576}
DEFAULT_MEMORY_BUDGET_MIB = 256
_random_bytes = os.urandom
CHUNK = 1 << 20
MAX_CHUNKS = (1 << 32) - 1
ZERO = bytes(12)
AUTH_ERROR = "Authentication failed: incorrect credentials or invalid container"


class FormatError(ValueError):
    pass


def encode(*fields):
    return b"".join(struct.pack(">I", len(field)) + field for field in fields)


def normalized(parts):
    if len(parts) != 3 or any(not isinstance(p, str) for p in parts):
        raise ValueError("Exactly three text parameters are required")
    result = tuple(unicodedata.normalize("NFC", p).encode("utf-8") for p in parts)
    if any(not 1 <= len(p) <= 1024 for p in result):
        raise ValueError("Each NFC parameter must contain 1 to 1024 UTF-8 bytes")
    return result


def generate_parameters():
    # 128 independently generated random bits in each ASCII segment.
    return tuple(secrets.token_hex(16) for _ in range(3))


def check_new_parameters(parts):
    p = normalized(parts)
    # Only a usability floor, NOT an entropy estimator.
    if any(len(x.decode("utf-8")) < 8 or not x.decode("utf-8").strip() for x in p):
        raise ValueError("Use at least eight characters per segment; random parameters recommended")
    if sum(len(x.decode("utf-8")) for x in p) < 24 or len(set(p)) != 3:
        raise ValueError("Use three distinct segments of at least 24 characters in total")
    return p


def mac(key, data):
    return hmac.digest(key, data, "sha256")


def suite_memory(suite):
    if type(suite) is not int or suite not in SUITES:
        raise FormatError("Unsupported container suite")
    return SUITES[suite]


def expand(prk, label, file_id, *fields, suite=SUITE):
    suite_memory(suite)
    info = encode(b"MOSAIC-HDT/v2", label, file_id, struct.pack(">H", suite), *fields)
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(prk)


def password_key(parts, salt, suite=SUITE):
    return hash_secret_raw(encode(*normalized(parts)), salt, time_cost=3,
                           memory_cost=suite_memory(suite), parallelism=4, hash_len=32,
                           type=Type.ID, version=19)


def credential_keys(material, parts, file_id, salt_p, salt_t, suite=SUITE):
    if len(material) != KEY_BYTES:
        raise ValueError("Invalid keyfile material length")
    kt = mac(salt_t, material)
    kp = password_key(parts, salt_p, suite)
    prk = mac(kt, kp)
    return expand(prk, b"wrap", file_id, suite=suite), expand(prk, b"commit", file_id, suite=suite)


def data_keys(root, file_id, suite=SUITE):
    return tuple(expand(root, purpose, file_id, suite=suite) for purpose in (b"header", b"data", b"final"))


def chunk_key(data_key, file_id, index, suite=SUITE):
    return expand(data_key, b"chunk", file_id, struct.pack(">Q", index), suite=suite)


def self_test():
    # RFC 8452 Appendix C.2: AES-256-GCM-SIV, empty plaintext and AAD.
    try:
        cipher = AESGCMSIV(b"\x01" + bytes(31))
        nonce = b"\x03" + bytes(11)
        expected = bytes.fromhex("07f5f4169bbf55a8400cd47ea6fd400f")
        if cipher.encrypt(nonce, b"", b"") != expected or cipher.decrypt(nonce, expected, b"") != b"":
            raise RuntimeError("AES-GCM-SIV known-answer test failed")
    except UnsupportedAlgorithm as exc:
        raise RuntimeError("AES-GCM-SIV unavailable; install a supported cryptography wheel; no fallback") from exc


def exact(stream, size):
    value = stream.read(size)
    if len(value) != size:
        raise FormatError("Truncated or invalid container")
    return value


@contextmanager
def atomic_output(destination):
    destination = Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    if os.name == "nt":
        from .windows_private import private_temp
        fd, name = private_temp(destination.parent)
    else:
        fd, name = tempfile.mkstemp(prefix=".mosaic-hdt-", suffix=".tmp", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            yield out
            out.flush()
            os.fsync(out.fileno())
        # No replacement or unsafe fallback. Unsupported filesystems fail closed.
        os.link(name, destination)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def regular_source(path):
    if not stat.S_ISREG(Path(path).stat().st_mode):
        raise ValueError("Only regular files are supported")


def generate_keyfile(destination):
    raw = KEY_MAGIC + struct.pack(">H", VERSION) + SHAPE + os.urandom(16) + os.urandom(KEY_BYTES)
    with atomic_output(destination) as out:
        out.write(raw + hashlib.sha256(raw).digest())


def read_keyfile(path):
    regular_source(path)
    with Path(path).open("rb") as inp:
        raw = exact(inp, KEY_SIZE)
        if inp.read(1):
            raise FormatError("Invalid keyfile length")
    if raw[:19] != KEY_MAGIC + struct.pack(">H", VERSION) + SHAPE:
        raise FormatError("Unsupported keyfile format")
    if not hmac.compare_digest(raw[-32:], hashlib.sha256(raw[:-32]).digest()):
        raise FormatError("Keyfile damage detected")
    return raw[35:-32]


def encrypt(source, destination, keyfile, parts, *, suite=SUITE):
    suite_memory(suite)
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    self_test()
    check_new_parameters(parts)
    regular_source(source)
    material = read_keyfile(keyfile)
    file_id, salt_p, salt_t = _random_bytes(16), _random_bytes(32), _random_bytes(32)
    head = HEADER.pack(MAGIC, VERSION, suite, file_id, salt_p, salt_t)
    kw, kc = credential_keys(material, parts, file_id, salt_p, salt_t, suite)
    del material
    root = _random_bytes(32)
    commitment = mac(kc, head)
    wrapped = AESGCMSIV(kw).encrypt(ZERO, root, head + commitment)
    kh, kd, kf = data_keys(root, file_id, suite)
    del root, kw, kc
    prefix = head + commitment + wrapped
    full_header = prefix + mac(kh, prefix)
    del kh
    digest = hashlib.sha256(full_header).digest()
    count = total = 0
    with Path(source).open("rb") as inp, atomic_output(destination) as out:
        out.write(full_header)
        while True:
            block = inp.read(CHUNK)
            if not block:
                break
            if count >= MAX_CHUNKS:
                raise ValueError("File exceeds format limits")
            record = RECORD.pack(1, count, len(block))
            ciphertext = AESGCMSIV(chunk_key(kd, file_id, count, suite)).encrypt(ZERO, block, digest + record)
            out.write(record + ciphertext)
            count += 1
            total += len(block)
            if len(block) < CHUNK:
                # A short record is canonical only at EOF.
                if inp.read(1):
                    raise OSError("Source changed during read")
                break
        out.write(b"\x02" + AESGCMSIV(kf).encrypt(ZERO, COUNTS.pack(count, total), digest + b"\x02"))


def decrypt(source, destination, keyfile, parts, *, max_memory_mib=DEFAULT_MEMORY_BUDGET_MIB):
    if max_memory_mib not in (64, 256, 512, 1024):
        raise ValueError("Choose a supported local memory budget")
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    self_test()
    regular_source(source)
    try:
        with Path(source).open("rb") as inp:
            head = exact(inp, HEADER.size)
            magic, version, suite, file_id, salt_p, salt_t = HEADER.unpack(head)
            if (magic, version) != (MAGIC, VERSION):
                raise FormatError("Unsupported container format")
            if suite_memory(suite) > max_memory_mib * 1024:
                raise FormatError("Suite exceeds local memory budget; explicitly authorize a higher budget")
            commitment, wrapped, header_mac = exact(inp, 32), exact(inp, 48), exact(inp, 32)
            material = read_keyfile(keyfile)
            kw, kc = credential_keys(material, parts, file_id, salt_p, salt_t, suite)
            del material
            if not hmac.compare_digest(commitment, mac(kc, head)):
                raise FormatError(AUTH_ERROR)
            root = AESGCMSIV(kw).decrypt(ZERO, wrapped, head + commitment)
            kh, kd, kf = data_keys(root, file_id, suite)
            del root, kw, kc
            prefix = head + commitment + wrapped
            if not hmac.compare_digest(header_mac, mac(kh, prefix)):
                raise FormatError(AUTH_ERROR)
            del kh
            digest = hashlib.sha256(prefix + header_mac).digest()
            count = total = 0
            short_seen = False
            with atomic_output(destination) as out:
                while True:
                    flag = exact(inp, 1)
                    if flag == b"\x02":
                        final = AESGCMSIV(kf).decrypt(ZERO, exact(inp, 32), digest + flag)
                        if COUNTS.unpack(final) != (count, total) or inp.read(1):
                            raise FormatError(AUTH_ERROR)
                        break
                    if flag != b"\x01" or short_seen or count >= MAX_CHUNKS:
                        raise FormatError(AUTH_ERROR)
                    record = flag + exact(inp, RECORD.size - 1)
                    _, index, length = RECORD.unpack(record)
                    if index != count or not 1 <= length <= CHUNK:
                        raise FormatError(AUTH_ERROR)
                    ciphertext = exact(inp, length + 16)
                    block = AESGCMSIV(chunk_key(kd, file_id, count, suite)).decrypt(ZERO, ciphertext, digest + record)
                    out.write(block)
                    count += 1
                    total += length
                    short_seen = length < CHUNK
    except InvalidTag as exc:
        raise FormatError(AUTH_ERROR) from exc


def prompt_parameters(confirm=False):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        values = tuple(getpass.getpass(f"Secret {i}: ") for i in range(1, 4))
        if confirm:
            again = tuple(getpass.getpass(f"Confirm secret {i}: ") for i in range(1, 4))
            if normalized(values) != normalized(again):
                raise ValueError("Confirmation does not match")
    return values


def list_residuals(directory):
    """Report candidates only; a live process may still own any candidate."""
    import re
    with os.scandir(directory) as entries:
        return sorted(entry.name for entry in entries
                      if re.fullmatch(r"\.mosaic-hdt-[A-Za-z0-9_-]+\.tmp", entry.name)
                      and entry.is_file(follow_symlinks=False))


def main():
    parser = argparse.ArgumentParser(description="Experimental MOSAIC-HDT v2")
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("self-test")
    residuals = subs.add_parser("list-residuals", help="List possible crash remnants; never deletes")
    residuals.add_argument("directory")
    keygen = subs.add_parser("generate-key")
    keygen.add_argument("destination")
    for name in ("encrypt", "decrypt"):
        p = subs.add_parser(name)
        p.add_argument("source")
        p.add_argument("destination")
        p.add_argument("--keyfile", required=True)
        if name == "encrypt":
            p.add_argument("--suite", type=int, choices=tuple(SUITES), default=2)
        else:
            p.add_argument("--max-memory-mib", type=int, choices=(64, 256, 512, 1024), default=DEFAULT_MEMORY_BUDGET_MIB)
    args = parser.parse_args()
    try:
        self_test()
        if args.action == "generate-key":
            generate_keyfile(args.destination)
        elif args.action == "list-residuals":
            for name in list_residuals(args.directory):
                print(repr(name))
            print("Do not remove candidates until all encryption processes have stopped.")
        elif args.action in ("encrypt", "decrypt"):
            if args.action == "encrypt":
                print("Use three independent randomly generated secrets; minimum length is not an entropy guarantee.")
            parts = prompt_parameters(args.action == "encrypt")
            try:
                if args.action == "encrypt":
                    encrypt(args.source, args.destination, args.keyfile, parts, suite=args.suite)
                else:
                    decrypt(args.source, args.destination, args.keyfile, parts, max_memory_mib=args.max_memory_mib)
            finally:
                del parts
        print("Completed.")
    except (OSError, ValueError, RuntimeError, getpass.GetPassWarning) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
