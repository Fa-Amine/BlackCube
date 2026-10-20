"""Encrypted, local-only vault state, folders, and password accounts."""
from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import string
import tempfile
import uuid
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .crypto import (VaultError, b64, unb64, PROFILES, generate_hybrid_keypair,
                     encrypt_file, decrypt_file, verify_encrypted_file, hash_file, HASHES)

VERSION = 1
MAX_META = 512 * 1024
MAX_STATE = 16 * 1024 * 1024
KDF_MEMORY_KIB = 64 * 1024
KDF_ITERATIONS = 3
KDF_LANES = 2
STATE_MAGIC = b"BCSTATE1"
KEY_FILE_BYTES = 32


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_home() -> Path:
    if os.name == "nt":
        return Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "BlackCube" / "vaults"
    return Path.home() / ".local" / "share" / "BlackCube" / "vaults"


def _ensure_private(path: Path, directory: bool = False) -> None:
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".blackcube-", suffix=".tmp", mode="wb",
                                     dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            _ensure_private(tmp)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
        _ensure_private(path)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def _vault_write_lock(directory: Path, timeout: float = 5.0):
    """Cross-process exclusive lock for metadata commits (Windows and POSIX).

    The lock file contains no secrets and is never included in backups.
    """
    directory = Path(directory)
    path = directory / '.vault-write.lock'
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    if os.name == 'nt':
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        if os.fstat(fd).st_size == 0:
            os.write(fd, b'0')
        os.lseek(fd, 0, os.SEEK_SET)
    else:
        import fcntl
    acquired = False
    start_time = time.monotonic()
    try:
        while not acquired:
            try:
                if os.name == 'nt':
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except (OSError, BlockingIOError) as exc:
                if time.monotonic() - start_time >= timeout:
                    raise VaultError('Vault is busy in another process; retry after closing other instances') from exc
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                if os.name == 'nt':
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _file_snapshot(path: Path) -> bytes | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_STATE + MAX_META:
        raise VaultError('Invalid or oversized vault metadata')
    return hashlib.sha256(path.read_bytes()).digest()

def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True).encode("utf-8")


def _password_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS,
                  memory_cost: int = KDF_MEMORY_KIB, lanes: int = KDF_LANES) -> bytes:
    if not password:
        raise VaultError("Master passphrase cannot be blank")
    # Explicit bounds prevent malicious/corrupt config from requesting huge allocations.
    if not (1 <= iterations <= 8 and 8192 <= memory_cost <= 262144 and 1 <= lanes <= 8):
        raise VaultError("Invalid or unsupported Argon2id parameters")
    if len(salt) != 16:
        raise VaultError("Invalid KDF salt")
    return Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes,
                    memory_cost=memory_cost).derive(password.encode("utf-8"))


def _master_aad(vault_id: str) -> bytes:
    return ("blackcube:vault-master:v1:" + vault_id).encode("ascii")


def _keyfile_key(key_file: Path, vault_id: str) -> bytes:
    """Key files contain raw 256-bit OS randomness; possession alone unlocks the vault."""
    path = Path(key_file)
    if path.is_symlink() or not path.is_file() or path.stat().st_size != KEY_FILE_BYTES:
        raise VaultError("Invalid BlackCube key file (32 bytes required)")
    with path.open("rb") as handle:
        secret = handle.read(KEY_FILE_BYTES + 1)
    if len(secret) != KEY_FILE_BYTES:
        raise VaultError("Invalid BlackCube key file")
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=bytes.fromhex(vault_id), info=b"BlackCube-v1-keyfile-master-wrap").derive(secret)


def _dual_key(config: dict, password: str, key_file: Path) -> bytes:
    """Combine BOTH authentication secrets; neither factor is a valid wrapper by itself.

    The Argon2id output is never stored. The 256-bit generated key file
    contributes independent entropy through a per-vault HKDF derivation.
    """
    params = config["kdf"]
    password_material = _password_key(password, unb64(params["salt"]),
        params["iterations"], params["memory_kib"], params["lanes"])
    file_material = _keyfile_key(key_file, config["vault_id"])
    wrapper = config["dual_wrap"]
    salt = unb64(wrapper["salt"])
    if len(salt) != 32:
        raise VaultError("Invalid dual-unlock salt")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
        info=b"BlackCube-v2-password-and-keyfile:" + bytes.fromhex(config["vault_id"])
    ).derive(password_material + file_material)


def _unwrap_master(config: dict, password: str | None = None,
                   key_file: Path | None = None) -> bytes:
    """Legacy configs retain EITHER-factor access; hardened configs enforce a policy."""
    mode = config.get("unlock_mode", "either")
    if mode not in ("either", "passphrase", "keyfile", "both"):
        raise VaultError("Unsupported vault authentication policy")
    if (mode == "both" and (password is None or key_file is None)) or (
        mode == "passphrase" and (password is None or key_file is not None)) or (
        mode == "keyfile" and (key_file is None or password is not None)) or (
        mode == "either" and ((password is None) == (key_file is None))):
        raise VaultError("Credentials do not match this vault's unlock policy")
    vault_id = config["vault_id"]
    try:
        if mode == "both":
            wrapper = config["dual_wrap"]
            key = _dual_key(config, password, Path(key_file))
        elif key_file is not None:
            wrapper = config.get("keyfile_wrap")
            if not wrapper:
                raise VaultError("No valid key-file unlock is configured")
            key = _keyfile_key(Path(key_file), vault_id)
        else:
            wrapper = config["master_wrap"]
            params = config["kdf"]
            key = _password_key(password, unb64(params["salt"]), params["iterations"],
                                params["memory_kib"], params["lanes"])
        master = AESGCM(key).decrypt(unb64(wrapper["nonce"]),
                    unb64(wrapper["ciphertext"]), _master_aad(vault_id))
        if len(master) != 32:
            raise VaultError("Invalid master key")
        return master
    except InvalidTag as exc:
        raise VaultError("Incorrect credentials or modified vault") from exc
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise VaultError("Invalid vault unlock information") from exc


def _state_aad(vault_id: str) -> bytes:
    return ("blackcube:encrypted-index:v1:" + vault_id).encode("ascii")


def _check_name(name: str) -> str:
    name = name.strip()
    if not (1 <= len(name) <= 100):
        raise VaultError("Project name must contain 1–100 characters")
    return name


def _safe_relative(relative: str) -> Path:
    # Filenames originate from a plaintext user selection, but the index can be
    # edited or corrupted; never trust saved paths on restore.
    p = PurePosixPath(relative)
    if not relative or p.is_absolute() or "\\" in relative or ":" in relative or any(
        c in ("", ".", "..") for c in relative.split("/")):
        raise VaultError("Unsafe stored file path")
    return Path(*p.parts)


def _read_config(directory: Path) -> dict:
    path = directory / "vault.json"
    if path.stat().st_size > MAX_META:
        raise VaultError("Vault metadata too large")
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("version") != VERSION:
        raise VaultError("Unsupported vault version")
    if not re.fullmatch(r"[0-9a-f]{32}", config.get("vault_id", "")):
        raise VaultError("Invalid vault identifier")
    if config.get("kdf", {}).get("name") != "Argon2id":
        raise VaultError("Unsupported password KDF")
    return config


def list_vault_dirs(home: Path | None = None) -> list[Path]:
    home = Path(home or default_home())
    if not home.exists():
        return []
    return sorted((folder for folder in home.iterdir() if folder.is_dir()
                   and not folder.is_symlink() and (folder / "vault.json").is_file()),
                  key=lambda d: d.name)


def create_vault(name: str, password: str, profile: str | None = "ML-KEM-768",
                 home: Path | None = None) -> "VaultSession":
    name = _check_name(name)
    if len(password) < 12:
        raise VaultError("Use a master passphrase of at least 12 characters")
    if profile is not None and profile not in PROFILES:
        raise VaultError("Unknown ML-KEM profile")
    home = Path(home or default_home())
    home.mkdir(parents=True, exist_ok=True)
    _ensure_private(home, directory=True)
    vault_id = uuid.uuid4().hex
    directory = home / vault_id
    directory.mkdir(mode=0o700)
    (directory / "objects").mkdir(mode=0o700)
    try:
        master = os.urandom(32)
        salt, nonce = os.urandom(16), os.urandom(12)
        wrapping = AESGCM(_password_key(password, salt)).encrypt(
            nonce, master, _master_aad(vault_id))
        public = None
        secret = None
        if profile:
            public, secret = generate_hybrid_keypair(profile)
        config = {"version": VERSION, "vault_id": vault_id,
                  "created_at": now(), "profile": profile,
                  "public_key": public,
                  "kdf": {"name": "Argon2id", "memory_kib": KDF_MEMORY_KIB,
                          "iterations": KDF_ITERATIONS, "lanes": KDF_LANES,
                          "salt": b64(salt)},
                  "master_wrap": {"nonce": b64(nonce), "ciphertext": b64(wrapping)}}
        state = {"name": name, "entries": [], "accounts": [],
                 "hybrid_private": secret,
                 "hybrid_public_digest": hashlib.sha256(_json_bytes(public)).hexdigest()}
        session = VaultSession(directory, config, master, state)
        _write_atomic(directory / "vault.json", _json_bytes(config))
        session._save()
        return session
    except BaseException:
        # Only attempt cleanup of a newly created, uncommitted vault directory.
        for path in (directory / "state.enc", directory / "vault.json"):
            path.unlink(missing_ok=True)
        try:
            (directory / "objects").rmdir()
            directory.rmdir()
        except OSError:
            pass
        raise


def open_vault(directory: Path, password: str | None = None,
               key_file: Path | None = None) -> "VaultSession":
    directory = Path(directory)
    config = _read_config(directory)
    master = _unwrap_master(config, password, key_file)
    try:
        state_path = directory / "state.enc"
        if state_path.stat().st_size > MAX_STATE:
            raise VaultError("Vault index too large")
        raw = state_path.read_bytes()
        if not raw.startswith(STATE_MAGIC) or len(raw) < len(STATE_MAGIC) + 29:
            raise VaultError("Corrupt encrypted index")
        nonce = raw[len(STATE_MAGIC):len(STATE_MAGIC) + 12]
        state = json.loads(AESGCM(master).decrypt(
            nonce, raw[len(STATE_MAGIC) + 12:], _state_aad(config["vault_id"])))
    except InvalidTag as exc:
        raise VaultError("Incorrect master passphrase or tampered vault") from exc
    except (KeyError, ValueError, TypeError) as exc:
        raise VaultError("Vault metadata is corrupt") from exc
    if not isinstance(state.get("entries"), list) or not isinstance(state.get("accounts"), list):
        raise VaultError("Invalid encrypted index")
    # A hash inside the authenticated index binds public keys to the private keys
    # and prevents undetected changes to the otherwise public vault config.
    public_digest = hashlib.sha256(_json_bytes(config.get("public_key"))).hexdigest()
    if state.get("hybrid_public_digest") != public_digest or (
        (state.get("hybrid_private") or {}).get("profile") != config.get("profile")):
        raise VaultError("Vault public keys or configuration have been modified")
    session = VaultSession(directory, config, master, state)
    session._last_state_snapshot = hashlib.sha256(raw).digest()
    session._last_config_snapshot = _file_snapshot(directory / 'vault.json')
    return session


class VaultSession:
    def __init__(self, directory: Path, config: dict, master: bytes, state: dict):
        self.directory = directory
        self.config = config
        self._master = master
        self._state = state
        self._last_state_snapshot = None
        self._last_config_snapshot = hashlib.sha256(_json_bytes(config)).digest()

    def _commit_config(self, updated: dict) -> None:
        """Refuse to overwrite credentials changed by another BlackCube process."""
        path = self.directory / 'vault.json'
        with _vault_write_lock(self.directory):
            if _file_snapshot(path) != self._last_config_snapshot:
                raise VaultError('Vault credentials changed in another process; lock and reopen the vault')
            raw = _json_bytes(updated)
            _write_atomic(path, raw)
            self._last_config_snapshot = hashlib.sha256(raw).digest()
            self.config = updated

    @property
    def name(self) -> str:
        return self._state["name"]

    @property
    def vault_id(self) -> str:
        return self.config["vault_id"]

    @property
    def profile(self) -> str | None:
        return self.config["profile"]

    @property
    def entries(self) -> list[dict]:
        return [dict(x) for x in self._state["entries"]]

    @property
    def accounts(self) -> list[dict]:
        return [dict(x) for x in self._state["accounts"]]

    def _save(self) -> None:
        nonce = os.urandom(12)
        data = _json_bytes(self._state)
        if len(data) > MAX_STATE - 64:
            raise VaultError("Encrypted index limit reached")
        wrapped = AESGCM(self._master).encrypt(nonce, data, _state_aad(self.vault_id))
        path = self.directory / "state.enc"
        with _vault_write_lock(self.directory):
            if _file_snapshot(path) != self._last_state_snapshot:
                raise VaultError('Vault index was modified by another process; reopen the vault instead of overwriting')
            raw = STATE_MAGIC + nonce + wrapped
            _write_atomic(path, raw)
            self._last_state_snapshot = hashlib.sha256(raw).digest()

    def verify_unlock(self, password: str | None = None,
                      key_file: Path | None = None) -> None:
        """Reauthenticate before restoring plaintext, regardless of an unlocked UI."""
        if not secrets.compare_digest(_unwrap_master(self.config, password, key_file), self._master):
            raise VaultError("Credential does not match the current vault session")

    @property
    def unlock_mode(self) -> str:
        return self.config.get("unlock_mode", "either")

    def _new_key_file(self, output: Path) -> Path:
        """Create a 256-bit randomly generated secret, never within the vault.

        The file is deliberately created BEFORE switching unlock policy; a
        failure cannot strand a user with a vault requiring an absent key.
        """
        output = Path(output)
        if (output.is_symlink() or output.exists() or
            output.resolve().is_relative_to(self.directory.resolve())):
            raise VaultError("Choose a NEW key-file path outside the vault")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            _ensure_private(output)
            stream.write(os.urandom(KEY_FILE_BYTES))
            stream.flush()
            os.fsync(stream.fileno())
        return output

    def require_two_factors(self, passphrase: str, output: Path) -> Path:
        """Switch passphrase-access vault to enforced passphrase AND new key file.

        Removes ALL single-factor wrappers in a single atomic metadata write.
        Old copies/backups remain accessible with old credentials (no rotation).
        """
        if self.unlock_mode not in ("either", "passphrase"):
            raise VaultError("Switch to passphrase mode before enabling two factors")
        self.verify_unlock(password=passphrase)
        output = self._new_key_file(output)
        try:
            updated = json.loads(json.dumps(self.config))
            updated["unlock_mode"] = "both"
            updated["dual_wrap"] = {"salt": b64(os.urandom(32))}
            nonce = os.urandom(12)
            wrap_key = _dual_key(updated, passphrase, output)
            updated["dual_wrap"].update({"nonce": b64(nonce), "ciphertext": b64(
                AESGCM(wrap_key).encrypt(nonce, self._master, _master_aad(self.vault_id)))})
            updated.pop("master_wrap", None)
            updated.pop("keyfile_wrap", None)
            # Test the new policy before atomically committing it.
            if not secrets.compare_digest(_unwrap_master(updated, passphrase, output), self._master):
                raise VaultError("Generated factors cannot unlock the vault")
            self._commit_config(updated)
            return output
        except BaseException:
            output.unlink(missing_ok=True)
            raise

    def require_keyfile_only(self, passphrase: str, output: Path) -> Path:
        """Switch to one generated key file as the ONLY live-vault credential."""
        if self.unlock_mode not in ("either", "passphrase"):
            raise VaultError("Switch to passphrase mode before enabling key-file-only access")
        self.verify_unlock(password=passphrase)
        output = self._new_key_file(output)
        try:
            updated = json.loads(json.dumps(self.config))
            nonce = os.urandom(12)
            updated["unlock_mode"] = "keyfile"
            updated["keyfile_wrap"] = {"nonce": b64(nonce), "ciphertext": b64(
                AESGCM(_keyfile_key(output, self.vault_id)).encrypt(
                    nonce, self._master, _master_aad(self.vault_id)))}
            updated.pop("master_wrap", None)
            updated.pop("dual_wrap", None)
            if not secrets.compare_digest(_unwrap_master(updated, key_file=output), self._master):
                raise VaultError("Generated key file cannot unlock the vault")
            self._commit_config(updated)
            return output
        except BaseException:
            output.unlink(missing_ok=True)
            raise

    def require_passphrase_only(self, new_passphrase: str, *,
                                current_passphrase: str | None = None,
                                current_key_file: Path | None = None) -> None:
        """Reconfigure access with a new passphrase after verifying current policy."""
        if len(new_passphrase) < 12:
            raise VaultError("Use at least 12 characters for the new passphrase")
        self.verify_unlock(password=current_passphrase, key_file=current_key_file)
        updated = json.loads(json.dumps(self.config))
        salt, nonce = os.urandom(16), os.urandom(12)
        updated["unlock_mode"] = "passphrase"
        updated["kdf"] = {"name": "Argon2id", "memory_kib": KDF_MEMORY_KIB,
                          "iterations": KDF_ITERATIONS, "lanes": KDF_LANES,
                          "salt": b64(salt)}
        updated["master_wrap"] = {"nonce": b64(nonce), "ciphertext": b64(
            AESGCM(_password_key(new_passphrase, salt)).encrypt(
                nonce, self._master, _master_aad(self.vault_id)))}
        updated.pop("keyfile_wrap", None)
        updated.pop("dual_wrap", None)
        if not secrets.compare_digest(_unwrap_master(updated, password=new_passphrase), self._master):
            raise VaultError("New passphrase verification failed")
        self._commit_config(updated)

    def add_keyfile(self, password: str, output: Path) -> Path:
        """Create a standalone recovery key file without invalidating the passphrase."""
        if self.unlock_mode != "either":
            raise VaultError("Alternate recovery keys are available only in legacy either-factor mode")
        self.verify_unlock(password=password)
        if self.config.get("keyfile_wrap"):
            raise VaultError("This vault already has a key file; replacement is not implemented")
        output = Path(output)
        if output.is_symlink() or output.exists():
            raise VaultError("Key-file destination already exists")
        if output.resolve().is_relative_to(self.directory.resolve()):
            raise VaultError("Store the key file separately from its encrypted vault")
        output.parent.mkdir(parents=True, exist_ok=True)
        secret = os.urandom(KEY_FILE_BYTES)
        try:
            with output.open("xb") as f:
                _ensure_private(output)
                f.write(secret)
                f.flush()
                os.fsync(f.fileno())
            derived = _keyfile_key(output, self.vault_id)
            nonce = os.urandom(12)
            updated = json.loads(json.dumps(self.config))
            updated["keyfile_wrap"] = {"nonce": b64(nonce), "ciphertext": b64(
                AESGCM(derived).encrypt(nonce, self._master, _master_aad(self.vault_id)))}
            self._commit_config(updated)
            return output
        except BaseException:
            output.unlink(missing_ok=True)
            raise

    def disable_keyfile(self, passphrase: str) -> None:
        """Disable current recovery-key authentication in the LIVE vault config.

        This cannot revoke keys against older stolen copies of this vault. A
        full master-key rotation/re-encryption is needed for that threat model.
        """
        if self.unlock_mode != "either":
            raise VaultError("Switch to passphrase-only mode to disable the active key requirement")
        self.verify_unlock(password=passphrase)
        if not self.config.get("keyfile_wrap"):
            raise VaultError("No recovery key is enabled")
        updated = json.loads(json.dumps(self.config))
        updated.pop("keyfile_wrap", None)
        self._commit_config(updated)

    def replace_keyfile(self, passphrase: str, output: Path) -> Path:
        """Atomically replace the active recovery credential in vault.json."""
        if self.unlock_mode != "either":
            raise VaultError("Use dedicated key-file rotation for a required-factor vault")
        self.verify_unlock(password=passphrase)
        output = Path(output)
        if output.is_symlink() or output.exists() or output.resolve().is_relative_to(self.directory.resolve()):
            raise VaultError("Select a new key-file path outside the vault")
        secret = os.urandom(KEY_FILE_BYTES)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("xb") as f:
                _ensure_private(output)
                f.write(secret)
                f.flush()
                os.fsync(f.fileno())
            derived = _keyfile_key(output, self.vault_id)
            nonce = os.urandom(12)
            updated = json.loads(json.dumps(self.config))
            updated["keyfile_wrap"] = {"nonce": b64(nonce), "ciphertext": b64(
                AESGCM(derived).encrypt(nonce, self._master, _master_aad(self.vault_id)))}
            self._commit_config(updated)
            return output
        except BaseException:
            output.unlink(missing_ok=True)
            raise

    def change_passphrase(self, old: str, new: str, key_file: Path | None = None) -> None:
        if len(new) < 12:
            raise VaultError("Use at least 12 characters for the new passphrase")
        if self.unlock_mode == "keyfile":
            raise VaultError("This vault has no passphrase; switch to passphrase-only mode")
        if self.unlock_mode == "both":
            if key_file is None:
                raise VaultError("Current key file is required to change a two-factor passphrase")
            self.verify_unlock(password=old, key_file=key_file)
            updated = json.loads(json.dumps(self.config))
            salt, nonce = os.urandom(16), os.urandom(12)
            updated["kdf"]["salt"] = b64(salt)
            updated["dual_wrap"] = {"salt": b64(os.urandom(32))}
            wrap_key = _dual_key(updated, new, key_file)
            updated["dual_wrap"].update({"nonce": b64(nonce), "ciphertext": b64(
                AESGCM(wrap_key).encrypt(nonce, self._master, _master_aad(self.vault_id)))})
            if not secrets.compare_digest(_unwrap_master(updated, new, key_file), self._master):
                raise VaultError("Updated two-factor credential failed verification")
            self._commit_config(updated)
            return
        if len(new) < 12:
            raise VaultError("Use at least 12 characters for the new passphrase")
        params = self.config["kdf"]
        old_key = _password_key(old, unb64(params["salt"]), params["iterations"],
                                params["memory_kib"], params["lanes"])
        try:
            if AESGCM(old_key).decrypt(unb64(self.config["master_wrap"]["nonce"]),
                unb64(self.config["master_wrap"]["ciphertext"]),
                _master_aad(self.vault_id)) != self._master:
                raise VaultError("Incorrect current passphrase")
        except InvalidTag as exc:
            raise VaultError("Incorrect current passphrase") from exc
        salt, nonce = os.urandom(16), os.urandom(12)
        updated = json.loads(json.dumps(self.config))
        updated["kdf"]["salt"] = b64(salt)
        updated["master_wrap"] = {"nonce": b64(nonce), "ciphertext": b64(
            AESGCM(_password_key(new, salt)).encrypt(nonce, self._master,
                _master_aad(self.vault_id)))}
        self._commit_config(updated)

    def _validate_source(self, path: Path) -> None:
        if path.is_symlink():
            raise VaultError("Symbolic links are excluded for safety")
        if not path.is_file():
            raise VaultError("Not a regular readable file")
        resolved = path.resolve()
        if resolved.is_relative_to(self.directory.resolve()):
            raise VaultError("Cannot import a file from inside its vault")

    def _import_file(self, source: Path, relative: str, mode: str,
                     hash_algorithm: str, hash_only: bool,
                     remove_original: bool = False) -> tuple[dict, str | None]:
        self._validate_source(source)
        _safe_relative(relative)
        if hash_algorithm not in HASHES:
            raise VaultError("Unsupported integrity algorithm")
        if remove_original and hash_only:
            raise VaultError("Cannot remove originals when only saving a hash")
        original_stat = source.stat()
        if remove_original and source.name.lower().endswith((".bckey", ".cube-key")):
            raise VaultError("Refusing to delete a generated encryption key file")
        if remove_original and original_stat.st_nlink != 1:
            raise VaultError("Refusing deletion of a file with hard links")
        new_id = uuid.uuid4().hex
        entry = {"id": new_id, "path": relative, "added_at": now(),
                 "bytes": original_stat.st_size, "hash_algorithm": hash_algorithm,
                 "type": "hash" if hash_only else "encrypted",
                 "mode": "Hash only" if hash_only else mode, "source_removed": False}
        object_path = self.directory / "objects" / (new_id + ".bcube")
        staged_path = self.directory / "staging" / (new_id + ".pending")
        staged_path.parent.mkdir(mode=0o700, exist_ok=True)
        if hash_only:
            entry["digest"] = hash_file(source, hash_algorithm)
        else:
            try:
                entry["digest"] = encrypt_file(source, staged_path, self._master,
                    self.vault_id, mode, self.config["public_key"], hash_algorithm)
            except BaseException:
                staged_path.unlink(missing_ok=True)
                raise
            try:
                confirmed = verify_encrypted_file(staged_path, self._master, self.vault_id,
                    self._state.get("hybrid_private"), hash_algorithm)
                if not secrets.compare_digest(confirmed, entry["digest"]):
                    raise VaultError("Authenticated readback mismatch")
                os.replace(staged_path, object_path)
            except BaseException:
                staged_path.unlink(missing_ok=True)
                raise
        self._state["entries"].append(entry)
        try:
            self._save()
        except BaseException:
            self._state["entries"].pop()
            if not hash_only:
                object_path.unlink(missing_ok=True)
            raise
        # The entry is fully committed. Deletion is never attempted for hash-only
        # imports and is never attempted if authenticated readback fails.
        if remove_original:
            try:
                digest = verify_encrypted_file(object_path, self._master, self.vault_id,
                    self._state.get("hybrid_private"), hash_algorithm)
                if not secrets.compare_digest(digest, entry["digest"]):
                    raise VaultError("Verified plaintext does not match the saved digest")
                # Prevent removing a source replaced/modified during the import.
                current_stat = source.lstat()
                if (source.is_symlink() or not source.is_file() or
                    current_stat.st_nlink != 1 or
                    (current_stat.st_dev, current_stat.st_ino, current_stat.st_size,
                     current_stat.st_mtime_ns, current_stat.st_ctime_ns) !=
                    (original_stat.st_dev, original_stat.st_ino, original_stat.st_size,
                     original_stat.st_mtime_ns, original_stat.st_ctime_ns) or
                    not secrets.compare_digest(hash_file(source, hash_algorithm), digest)):
                    raise VaultError("Original changed during import: retained")
                source.unlink()
            except (OSError, VaultError, ValueError) as exc:
                return entry, f"{relative}: encrypted record saved; source removal skipped/failed: {exc}"
            entry["source_removed"] = True
            try:
                self._save()
            except (OSError, VaultError, ValueError) as exc:
                # The source is already removed; don't misreport it as retained.
                return entry, f"{relative}: original DELETED; status update failed: {exc}. Encrypted record was saved before deletion."
        return entry, None

    def import_path(self, path: Path, mode: str = "AES-256-GCM",
                    hash_algorithm: str = "SHA-256", hash_only: bool = False,
                    progress=None, remove_original: bool = False) -> tuple[int, list[str]]:
        """Save individual objects; optionally unlink a source only after authenticated readback.

        Deletion is ordinary OS unlink, NOT forensic secure erase. No rollback of
        already processed files in a multi-file batch; report every partial failure.
        """
        path = Path(path)
        if path.is_symlink():
            raise VaultError("Symbolic links cannot be imported")
        if not path.is_file() and not path.is_dir():
            raise VaultError("Select an existing file or folder")
        if mode not in ("AES-256-GCM", "AES-128-GCM", "AES-192-GCM", "ChaCha20-Poly1305", "Hybrid " + str(self.profile)):
            if not hash_only:
                raise VaultError("Encryption mode not enabled for this vault")
        if remove_original and hash_only:
            raise VaultError("Hash records cannot replace files")
        # Exclude the vault and its home. Never ingest or delete vault objects.
        selected_root = path.resolve()
        if self.directory.resolve().is_relative_to(selected_root):
            raise VaultError("Source contains the encrypted vault directory")
        count, warnings = 0, []
        if path.is_file():
            pairs = [(path, path.name)]
        else:
            pairs = []
            for root, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
                for filename in sorted(files):
                    source = Path(root) / filename
                    if source.is_symlink():
                        warnings.append(f"Skipped symlink: {filename}")
                        continue
                    pairs.append((source, (Path(path.name) / source.relative_to(path)).as_posix()))
        for source, relative in pairs:
            try:
                _, warning = self._import_file(source, relative, mode, hash_algorithm,
                                               hash_only, remove_original)
                count += 1
                if warning:
                    warnings.append(warning)
                if progress:
                    progress(count, len(pairs), relative)
            except (OSError, VaultError, ValueError) as exc:
                warnings.append(f"{relative}: {exc}")
        return count, warnings

    def import_files(self, paths: list[Path], mode: str = "AES-256-GCM",
                     hash_algorithm: str = "SHA-256", hash_only: bool = False,
                     progress=None, remove_original: bool = False) -> tuple[int, list[str]]:
        """Add multiple selections through native multi-file picker."""
        total, warnings = 0, []
        for i, path in enumerate(paths):
            count, issues = self.import_path(Path(path), mode, hash_algorithm,
                                             hash_only, remove_original=remove_original)
            total += count
            warnings.extend(issues)
            if progress:
                progress(i + 1, len(paths), str(path))
        return total, warnings

    def _entry(self, entry_id: str) -> dict:
        return next((e for e in self._state["entries"] if e["id"] == entry_id), None) or self._missing()

    @staticmethod
    def _missing():
        raise VaultError("Entry not found")

    def restore(self, entry_id: str, output_folder: Path) -> Path:
        entry = self._entry(entry_id)
        if entry["type"] != "encrypted":
            raise VaultError("A hash record contains no recoverable file")
        relative = _safe_relative(entry["path"])
        root = Path(output_folder).resolve()
        if not root.is_dir():
            raise VaultError("Choose an existing output folder")
        if root.is_relative_to(self.directory.resolve()):
            raise VaultError("Cannot restore into the vault data directory")
        target = root / relative
        if not target.resolve().is_relative_to(root):
            raise VaultError("Unsafe restore destination")
        # Do not traverse pre-existing symlinked folders.
        cursor = root
        for part in relative.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise VaultError("Restore path traverses a symbolic link")
        decrypted_source = self.directory / "objects" / (entry_id + ".bcube")
        decrypt_file(decrypted_source, target, self._master, self.vault_id,
                     self._state.get("hybrid_private"))
        if hash_file(target, entry["hash_algorithm"]) != entry["digest"]:
            target.unlink(missing_ok=True)
            raise VaultError("Plaintext digest mismatch after restore")
        return target

    def verify_hash(self, entry_id: str, candidate: Path) -> bool:
        entry = self._entry(entry_id)
        return secrets.compare_digest(hash_file(candidate, entry["hash_algorithm"]),
                                       entry["digest"])

    def remove_entry(self, entry_id: str) -> None:
        entry = self._entry(entry_id)
        # Save updated index first; in case of failure, don't delete encrypted data.
        self._state["entries"] = [e for e in self._state["entries"] if e["id"] != entry_id]
        try:
            self._save()
        except BaseException:
            self._state["entries"].append(entry)
            raise
        if entry["type"] == "encrypted":
            (self.directory / "objects" / (entry_id + ".bcube")).unlink(missing_ok=True)

    def save_account(self, title: str, username: str, password: str, url: str = "",
                     notes: str = "", account_id: str | None = None) -> str:
        if not title.strip() or not password:
            raise VaultError("Account title and password are required")
        row = {"id": account_id or uuid.uuid4().hex, "title": title.strip(),
               "username": username, "password": password, "url": url,
               "notes": notes, "updated_at": now()}
        previous = self._state["accounts"]
        self._state["accounts"] = [a for a in previous if a["id"] != row["id"]] + [row]
        try:
            self._save()
        except BaseException:
            self._state["accounts"] = previous
            raise
        return row["id"]

    def delete_account(self, account_id: str) -> None:
        previous = self._state["accounts"]
        self._state["accounts"] = [a for a in previous if a["id"] != account_id]
        try:
            self._save()
        except BaseException:
            self._state["accounts"] = previous
            raise


def generate_password(length: int = 24) -> str:
    if not 12 <= length <= 128:
        raise VaultError("Password length must be between 12 and 128")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    return "".join(secrets.choice(alphabet) for _ in range(length))
