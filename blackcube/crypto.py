"""Versioned file envelope for BlackCube.

Data is encrypted with streaming AES-256-GCM. A random 256-bit file key is
wrapped either under the project's master key or via a hybrid ML-KEM + X25519
KEM. Header bytes are authenticated as GCM associated data. Filenames reside
in the separately encrypted vault index, not the file envelopes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"BCUBE1\x00"
MAX_HEADER = 16384
BLOCK = 1024 * 1024
TAG_SIZE = 16
# GCM imposes a per-(key,nonce) plaintext length bound; do not exceed it.
# 64 GiB minus a safety margin is the maximum accepted individual file size.
MAX_FILE_BYTES = (1 << 36) - 1024
HASHES = {"SHA-256": hashlib.sha256, "SHA3-256": hashlib.sha3_256,
          "SHA-512": hashlib.sha512, "SHA3-512": hashlib.sha3_512,
          "BLAKE2b-256": lambda: hashlib.blake2b(digest_size=32),
          "BLAKE2s-256": lambda: hashlib.blake2s(digest_size=32)}
NEW_CIPHERS = ("AES-128-GCM", "AES-192-GCM", "ChaCha20-Poly1305")
MAGIC2 = b"BCUBE2\x00"
MAX_CHUNK = 1024 * 1024
PROFILES = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")


class VaultError(Exception):
    """A safe-to-display vault or file error."""


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _kem(profile: str):
    if profile not in PROFILES:
        raise VaultError("Unsupported ML-KEM profile")
    try:
        from importlib import import_module
        return import_module("pqcrypto.kem." + profile.lower().replace("-", "_"))
    except ImportError as exc:
        raise VaultError("Post-quantum support requires pqcrypto>=1.0.0") from exc


def generate_hybrid_keypair(profile: str) -> tuple[dict, dict]:
    """Return a JSON-friendly public bundle and a secret bundle."""
    public_kem, secret_kem = _kem(profile).keygen()
    classical_private = x25519.X25519PrivateKey.generate()
    public = {
        "profile": profile,
        "ml_kem": b64(public_kem),
        "x25519": b64(classical_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
    }
    secret = {
        "profile": profile,
        "ml_kem": b64(secret_kem),
        "x25519": b64(classical_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())),
    }
    return public, secret


def _wrap_aad(vault_id: str, kind: str) -> bytes:
    return f"blackcube:wrapped-file-key:v1:{vault_id}:{kind}".encode("ascii")


def _wrap_file_key(file_key: bytes, master: bytes, vault_id: str,
                   mode: str, hybrid_public: dict | None) -> dict:
    if mode == "AES-256-GCM" or mode in NEW_CIPHERS:
        nonce = os.urandom(12)
        return {"kind": "vault", "nonce": b64(nonce),
                "ciphertext": b64(AESGCM(master).encrypt(
                    nonce, file_key, _wrap_aad(vault_id, "vault")))}
    if not mode.startswith("Hybrid ML-KEM-"):
        raise VaultError("Unsupported encryption mode")
    profile = mode.removeprefix("Hybrid ")
    if not hybrid_public or hybrid_public.get("profile") != profile:
        raise VaultError("This vault has no matching ML-KEM public key")
    kem_ct, kem_shared = _kem(profile).encaps(unb64(hybrid_public["ml_kem"]))
    ephemeral = x25519.X25519PrivateKey.generate()
    recipient = x25519.X25519PublicKey.from_public_bytes(unb64(hybrid_public["x25519"]))
    classic_shared = ephemeral.exchange(recipient)
    # Domain-separated HKDF combiner of BOTH independently established secrets.
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"blackcube:v1:hybrid-file-key:" + profile.encode("ascii")
                    ).derive(kem_shared + classic_shared)
    nonce = os.urandom(12)
    return {"kind": "hybrid", "profile": profile,
            "kem_ciphertext": b64(kem_ct),
            "ephemeral_x25519": b64(ephemeral.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(wrap_key).encrypt(
                nonce, file_key, _wrap_aad(vault_id, "hybrid:" + profile)))}


def _unwrap_file_key(wrapper: dict, master: bytes, vault_id: str,
                     hybrid_secret: dict | None) -> bytes:
    kind = wrapper.get("kind")
    if kind == "vault":
        return AESGCM(master).decrypt(unb64(wrapper["nonce"]),
            unb64(wrapper["ciphertext"]), _wrap_aad(vault_id, "vault"))
    if kind != "hybrid":
        raise VaultError("Unrecognized file-key wrapping mode")
    profile = wrapper.get("profile")
    if not hybrid_secret or hybrid_secret.get("profile") != profile:
        raise VaultError("The ML-KEM private key is missing for this file")
    kem_shared = _kem(profile).decaps(
        unb64(hybrid_secret["ml_kem"]), unb64(wrapper["kem_ciphertext"]))
    private = x25519.X25519PrivateKey.from_private_bytes(unb64(hybrid_secret["x25519"]))
    classic_shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(
        unb64(wrapper["ephemeral_x25519"])))
    wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"blackcube:v1:hybrid-file-key:" + profile.encode("ascii")
                    ).derive(kem_shared + classic_shared)
    return AESGCM(wrap_key).decrypt(unb64(wrapper["nonce"]),
        unb64(wrapper["ciphertext"]), _wrap_aad(vault_id, "hybrid:" + profile))


def hash_file(path: Path, algorithm: str = "SHA-256") -> str:
    if algorithm not in HASHES:
        raise VaultError("Unsupported hash function")
    hasher = HASHES[algorithm]()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(BLOCK):
            hasher.update(chunk)
    return hasher.hexdigest()


def encrypt_file(source: Path, target: Path, master: bytes, vault_id: str,
                 mode: str, hybrid_public: dict | None,
                 digest_algorithm: str = "SHA-256") -> str:
    """Encrypt without ever modifying source. Writes a new opaque .bcube file."""
    if digest_algorithm not in HASHES:
        raise VaultError("Unsupported digest")
    if mode in NEW_CIPHERS:
        return _encrypt_file_v2(source, target, master, vault_id, mode,
                                hybrid_public, digest_algorithm)
    source, target = Path(source), Path(target)
    if target.exists():
        raise VaultError("Encrypted output already exists")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise VaultError("File exceeds the single-envelope AES-GCM size limit")
    file_key, nonce = os.urandom(32), os.urandom(12)
    wrapper = _wrap_file_key(file_key, master, vault_id, mode, hybrid_public)
    header = {"v": 1, "vault_id": vault_id, "cipher": "AES-256-GCM",
              "nonce": b64(nonce), "wrapper": wrapper}
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(header_bytes) > MAX_HEADER:
        raise VaultError("Header exceeds format limit")
    prefix = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes
    encryptor = Cipher(algorithms.AES(file_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    hasher = HASHES[digest_algorithm]()
    processed = 0
    try:
        with source.open("rb") as inp, target.open("xb") as out:
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
            out.write(prefix)
            while chunk := inp.read(BLOCK):
                processed += len(chunk)
                if processed > MAX_FILE_BYTES:
                    raise VaultError("Input grew beyond AES-GCM size limit")
                hasher.update(chunk)
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize())
            out.write(encryptor.tag)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return hasher.hexdigest()


def decrypt_file(source: Path, destination: Path, master: bytes, vault_id: str,
                 hybrid_secret: dict | None) -> None:
    """Decrypt to an exclusive temporary file, publishing only after tag validation."""
    source, destination = Path(source), Path(destination)
    with source.open("rb") as detect:
        is_v2 = detect.read(len(MAGIC2)) == MAGIC2
    if is_v2:
        return _decrypt_file_v2(source, destination, master, vault_id, hybrid_secret)
    if destination.exists() or destination.is_symlink():
        raise VaultError("Destination already exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name("." + destination.name + "." + os.urandom(8).hex() + ".partial")
    try:
        with source.open("rb") as inp:
            prefix = inp.read(len(MAGIC) + 4)
            if len(prefix) != len(MAGIC) + 4 or not prefix.startswith(MAGIC):
                raise VaultError("Not a supported BlackCube encrypted file")
            header_size = struct.unpack(">I", prefix[len(MAGIC):])[0]
            if header_size <= 0 or header_size > MAX_HEADER:
                raise VaultError("Invalid file header size")
            raw_header = inp.read(header_size)
            if len(raw_header) != header_size:
                raise VaultError("Truncated file header")
            header = json.loads(raw_header)
            if header.get("v") != 1 or header.get("cipher") != "AES-256-GCM":
                raise VaultError("Unsupported BlackCube file version or cipher")
            if header.get("vault_id") != vault_id:
                raise VaultError("This file belongs to a different vault")
            nonce = unb64(header["nonce"])
            if len(nonce) != 12:
                raise VaultError("Invalid AES-GCM nonce")
            key = _unwrap_file_key(header["wrapper"], master, vault_id, hybrid_secret)
            payload_start = inp.tell()
            inp.seek(0, os.SEEK_END)
            total = inp.tell()
            if total < payload_start + TAG_SIZE:
                raise VaultError("Truncated encrypted file")
            inp.seek(total - TAG_SIZE)
            tag = inp.read(TAG_SIZE)
            inp.seek(payload_start)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(prefix + raw_header)
            remaining = total - payload_start - TAG_SIZE
            if remaining > MAX_FILE_BYTES:
                raise VaultError("Encrypted payload exceeds supported AES-GCM size limit")
            with temp.open("xb") as out:
                try:
                    os.chmod(temp, 0o600)
                except OSError:
                    pass
                while remaining:
                    chunk = inp.read(min(BLOCK, remaining))
                    if not chunk:
                        raise VaultError("Truncated encrypted payload")
                    remaining -= len(chunk)
                    out.write(decryptor.update(chunk))
                out.write(decryptor.finalize())
                out.flush()
                os.fsync(out.fileno())
        if destination.exists() or destination.is_symlink():
            raise VaultError("Destination appeared during decryption; refusing overwrite")
        # Publish the complete authenticated file only after successful verification.
        os.rename(temp, destination)
    except InvalidTag as exc:
        raise VaultError("Authentication failed: wrong key or modified data") from exc
    finally:
        temp.unlink(missing_ok=True)


def verify_encrypted_file(source: Path, master: bytes, vault_id: str,
                          hybrid_secret: dict | None,
                          digest_algorithm: str = "SHA-256") -> str:
    """Authenticate and hash decrypted plaintext WITHOUT creating a plaintext file.

    Readback verification is required before an opted-in source can be removed.
    """
    if digest_algorithm not in HASHES:
        raise VaultError("Unsupported digest")
    with Path(source).open("rb") as detect:
        if detect.read(len(MAGIC2)) == MAGIC2:
            return _process_v2(source, master, vault_id, hybrid_secret, digest_algorithm)
    hasher = HASHES[digest_algorithm]()
    with Path(source).open("rb") as inp:
        prefix = inp.read(len(MAGIC) + 4)
        if len(prefix) != len(MAGIC) + 4 or not prefix.startswith(MAGIC):
            raise VaultError("Invalid encrypted object header")
        header_size = struct.unpack(">I", prefix[len(MAGIC):])[0]
        if not 0 < header_size <= MAX_HEADER:
            raise VaultError("Invalid encrypted object header length")
        raw_header = inp.read(header_size)
        if len(raw_header) != header_size:
            raise VaultError("Truncated encrypted object header")
        try:
            header = json.loads(raw_header)
            if (header.get("v") != 1 or header.get("cipher") != "AES-256-GCM" or
                    header.get("vault_id") != vault_id):
                raise VaultError("Invalid encrypted object identity")
            nonce = unb64(header["nonce"])
            if len(nonce) != 12:
                raise VaultError("Invalid object nonce")
            key = _unwrap_file_key(header["wrapper"], master, vault_id, hybrid_secret)
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError("Malformed encrypted object header") from exc
        position = inp.tell()
        inp.seek(0, os.SEEK_END)
        total = inp.tell()
        remaining = total - position - TAG_SIZE
        if remaining < 0 or remaining > MAX_FILE_BYTES:
            raise VaultError("Truncated or oversized encrypted object")
        inp.seek(total - TAG_SIZE)
        tag = inp.read(TAG_SIZE)
        inp.seek(position)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        dec.authenticate_additional_data(prefix + raw_header)
        try:
            while remaining:
                chunk = inp.read(min(BLOCK, remaining))
                if not chunk:
                    raise VaultError("Truncated encrypted object")
                remaining -= len(chunk)
                hasher.update(dec.update(chunk))
            hasher.update(dec.finalize())
        except InvalidTag as exc:
            raise VaultError("Authenticated readback failed; source was retained") from exc
    return hasher.hexdigest()


# v2 uses independently authenticated 1-MiB records. Each chunk is bound to
# the complete header, ordinal, and explicit final record, preventing reorder,
# omission, and truncation. v1 AES-256-GCM envelopes remain readable forever.
def _v2_aead(cipher: str, file_key: bytes):
    if cipher == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(file_key)
    lengths = {"AES-128-GCM": 16, "AES-192-GCM": 24}
    if cipher not in lengths:
        raise VaultError("Unknown v2 cipher")
    return AESGCM(file_key[:lengths[cipher]])


def _v2_header(inp, master, vault_id, hybrid_secret):
    prefix = inp.read(len(MAGIC2) + 4)
    if not prefix.startswith(MAGIC2) or len(prefix) != len(MAGIC2) + 4:
        raise VaultError("Invalid v2 envelope")
    n = struct.unpack(">I", prefix[len(MAGIC2):])[0]
    if not 0 < n <= MAX_HEADER:
        raise VaultError("Invalid v2 header size")
    raw = inp.read(n)
    if len(raw) != n:
        raise VaultError("Truncated v2 header")
    try:
        h = json.loads(raw)
        if h.get("v") != 2 or h.get("vault_id") != vault_id:
            raise VaultError("Incorrect vault or envelope version")
        nonce_prefix = unb64(h["nonce_prefix"])
        if len(nonce_prefix) != 8:
            raise VaultError("Invalid v2 nonce")
        key = _unwrap_file_key(h["wrapper"], master, vault_id, hybrid_secret)
        cipher = _v2_aead(h["cipher"], key)
    except (ValueError, KeyError, TypeError) as exc:
        raise VaultError("Malformed encrypted header") from exc
    return prefix + raw, cipher, nonce_prefix


def _encrypt_file_v2(source, target, master, vault_id, mode, public, digest_algorithm):
    source, target = Path(source), Path(target)
    if target.exists() or target.is_symlink():
        raise VaultError("Encrypted output already exists")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise VaultError("File too large")
    key, salt8 = os.urandom(32), os.urandom(8)
    wrap = _wrap_file_key(key, master, vault_id, mode, public)
    header = json.dumps({"v": 2, "vault_id": vault_id, "cipher": mode,
        "nonce_prefix": b64(salt8), "wrapper": wrap}, sort_keys=True,
        separators=(",", ":")).encode()
    if len(header) > MAX_HEADER:
        raise VaultError("Header too long")
    prefix = MAGIC2 + struct.pack(">I", len(header)) + header
    aead, hasher = _v2_aead(mode, key), HASHES[digest_algorithm]()
    count, length = 0, 0
    try:
        with source.open("rb") as inp, target.open("xb") as out:
            out.write(prefix)
            while chunk := inp.read(MAX_CHUNK):
                length += len(chunk)
                if length > MAX_FILE_BYTES or count >= 2**32-1:
                    raise VaultError("File size limit exceeded")
                hasher.update(chunk)
                size = struct.pack(">I", len(chunk))
                nonce = salt8 + count.to_bytes(4, "big")
                out.write(size)
                out.write(aead.encrypt(nonce, chunk, prefix + count.to_bytes(8,"big") + size))
                count += 1
            # Authentication of this explicit terminal record rejects truncation.
            size = struct.pack(">I", 0)
            out.write(size)
            out.write(aead.encrypt(salt8 + count.to_bytes(4,"big"), b"",
                                   prefix + count.to_bytes(8,"big") + size))
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return hasher.hexdigest()


def _process_v2(source, master, vault_id, hybrid_secret, digest_algorithm, out=None):
    hasher = HASHES[digest_algorithm]()
    total, index = 0, 0
    with Path(source).open("rb") as inp:
        prefix, aead, salt8 = _v2_header(inp, master, vault_id, hybrid_secret)
        while True:
            size = inp.read(4)
            if len(size) != 4:
                raise VaultError("Missing final authenticated record")
            n = struct.unpack(">I", size)[0]
            if n > MAX_CHUNK or index >= 2**32:
                raise VaultError("Oversized or excessive record")
            ciphertext = inp.read(n + 16)
            if len(ciphertext) != n + 16:
                raise VaultError("Truncated record")
            try:
                plain = aead.decrypt(salt8 + index.to_bytes(4,"big"), ciphertext,
                              prefix + index.to_bytes(8,"big") + size)
            except InvalidTag as exc:
                raise VaultError("Authenticated chunk verification failed") from exc
            if n == 0:
                if inp.read(1):
                    raise VaultError("Unexpected trailing ciphertext")
                return hasher.hexdigest()
            total += n
            if total > MAX_FILE_BYTES:
                raise VaultError("Exceeded file size limit")
            hasher.update(plain)
            if out is not None:
                out.write(plain)
            index += 1


def _decrypt_file_v2(source, destination, master, vault_id, hybrid_secret):
    if destination.exists() or destination.is_symlink():
        raise VaultError("Destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name("." + destination.name + "." + os.urandom(8).hex() + ".partial")
    try:
        with temp.open("xb") as out:
            _process_v2(source, master, vault_id, hybrid_secret, "SHA-256", out)
            out.flush()
            os.fsync(out.fileno())
        if destination.exists() or destination.is_symlink():
            raise VaultError("Destination already exists")
        os.rename(temp, destination)
    finally:
        temp.unlink(missing_ok=True)
