"""Standalone .cubefile encrypted TAR stream, independent of BlackCube vaults.

No unencrypted archive is written during encryption. Restored files are written
in a private temporary directory and published only after full GCM validation.
Do not use on active/untrusted folders; see README for limitations.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import struct
import tarfile
import uuid
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .crypto import VaultError, BLOCK, MAX_FILE_BYTES
from .vault import _password_key, _ensure_private

MAGIC = b"CUBEFILE1\x00"
HEADER_MAX = 4096
MAX_FILES = 100_000
MAX_TOTAL = 64 * 1024**3 - 1024


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _ub64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def generate_portable_keyfile(path: Path) -> Path:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise VaultError('Key file already exists')
    with path.open('xb') as f:
        _ensure_private(path)
        f.write(os.urandom(32))
        f.flush()
        os.fsync(f.fileno())
    return path


def _credential_key(salt: bytes, passphrase: str | None, key_file: Path | None) -> bytes:
    if (passphrase is None) == (key_file is None):
        raise VaultError('Use either a passphrase or a key file')
    if passphrase is not None:
        if len(passphrase) < 12:
            raise VaultError('Passphrase requires at least 12 characters')
        return _password_key(passphrase, salt)
    key_file = Path(key_file)
    if key_file.is_symlink() or not key_file.is_file() or key_file.stat().st_size != 32:
        raise VaultError('Key file must be a regular 32-byte file')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b'blackcube-portable-keyfile-v1').derive(key_file.read_bytes())


def _inventory(source: Path):
    source = Path(source)
    if source.is_symlink() or not source.exists():
        raise VaultError('Select an existing non-symlink file or folder')
    if not source.is_file() and not source.is_dir():
        raise VaultError('Unsupported source type')
    yield source, source.name
    if source.is_dir():
        for root, dirs, files in os.walk(source, followlinks=False):
            for name in sorted(dirs):
                p = Path(root) / name
                if p.is_symlink():
                    raise VaultError('Folders with symlinks are unsupported')
                yield p, (Path(source.name) / p.relative_to(source)).as_posix()
            for name in sorted(files):
                p = Path(root) / name
                if p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1:
                    raise VaultError('Symlinks, special files and hardlinked files are unsupported')
                yield p, (Path(source.name) / p.relative_to(source)).as_posix()


class _EncryptWriter:
    def __init__(self, out, encryptor):
        self.out, self.encryptor, self.hasher, self.size = out, encryptor, hashlib.sha256(), 0

    def write(self, data):
        self.size += len(data)
        if self.size > MAX_TOTAL:
            raise VaultError('Standalone archive exceeds maximum size')
        self.hasher.update(data)
        self.out.write(self.encryptor.update(data))
        return len(data)

    def tell(self):
        return self.size


def _validate_safe_source(source: Path):
    if source.name.lower().endswith(('.bckey', '.cube-key', '.cubefile')):
        raise VaultError('Cannot encrypt an encrypted file or recovery key as a source')
    if not source.name or source.name in ('.', '..'):
        raise VaultError('Invalid source basename')
    total, count = 0, 0
    for p, name in _inventory(source):
        if '\\' in name or ':' in name or name.startswith('/'):
            raise VaultError('Unsupported path')
        if p.is_file():
            if p.suffix.lower() in ('.bckey', '.cube-key'):
                raise VaultError('Do not include recovery keys in a standalone archive')
            size = p.stat().st_size
            if size > MAX_FILE_BYTES:
                raise VaultError('Input file too large')
            total += size
            if total > MAX_TOTAL:
                raise VaultError('Folder exceeds maximum size')
        count += 1
        if count > MAX_FILES:
            raise VaultError('Folder has too many entries')


def encrypt_standalone(source: Path, *, passphrase: str | None = None,
                       key_file: Path | None = None, output: Path | None = None,
                       remove_original: bool = False,
                       cipher: str = "AES-256-GCM") -> Path:
    """Create source.cubefile in the same directory; original retained by default.

    remove_original is supported only for regular files. Folders are deliberately
    retained; deleting a tree with a portable archive is not atomic/safe enough.
    """
    if cipher not in ('AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM'):
        raise VaultError('Standalone encryption supports AES-GCM key lengths 128, 192 and 256')
    source = Path(source)
    _validate_safe_source(source)
    if remove_original and source.name.lower().endswith(('.bckey', '.cube-key')):
        raise VaultError('Refusing to remove an encryption credential file')
    if remove_original and source.is_dir():
        raise VaultError('Folder deletion is not supported; verify recovery and remove it manually')
    if remove_original and (source.stat().st_nlink != 1 or source.is_symlink()):
        raise VaultError('Cannot remove a linked source')
    if output is None:
        output = source.with_name(source.name + '.cubefile')
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise VaultError('Output already exists; refusing overwrite')
    if output.parent.resolve() != source.parent.resolve():
        raise VaultError('Standalone output must remain alongside its source')
    orig_stat = source.stat() if source.is_file() else None
    salt, wrap_nonce, nonce, file_key = os.urandom(16), os.urandom(12), os.urandom(12), os.urandom(32)
    wrapping_key = _credential_key(salt, passphrase, key_file)
    wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, file_key, b'blackcube:portable-key:v1')
    header = json.dumps({'v': 1, 'kdf': 'Argon2id' if passphrase is not None else 'keyfile-HKDF',
                         'salt': _b64(salt), 'wrap_nonce': _b64(wrap_nonce),
                         'wrapped': _b64(wrapped), 'nonce': _b64(nonce),
                         'cipher': cipher}, sort_keys=True, separators=(',', ':')).encode()
    prefix = MAGIC + struct.pack('>I', len(header)) + header
    tmp = output.with_name('.' + output.name + '.' + uuid.uuid4().hex + '.partial')
    try:
        with tmp.open('xb') as out:
            _ensure_private(tmp)
            out.write(prefix)
            bits = {'AES-256-GCM': 32, 'AES-192-GCM': 24, 'AES-128-GCM': 16}[cipher]
            encryptor = Cipher(algorithms.AES(file_key[:bits]), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(prefix)
            writer = _EncryptWriter(out, encryptor)
            # tarfile streams metadata and file bytes directly to encryption.
            with tarfile.open(fileobj=writer, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for i, (path, name) in enumerate(_inventory(source)):
                    if i >= MAX_FILES:
                        raise VaultError('Too many archive entries')
                    info = tar.gettarinfo(str(path), arcname=name)
                    if not (info.isfile() or info.isdir()):
                        raise VaultError('Unsupported filesystem entry')
                    if info.isfile():
                        old = path.stat()
                        with path.open('rb') as stream:
                            tar.addfile(info, stream)
                        new = path.stat()
                        if (old.st_size, old.st_mtime_ns, old.st_ctime_ns) != (new.st_size, new.st_mtime_ns, new.st_ctime_ns):
                            raise VaultError('Source changed during encryption')
                    else:
                        tar.addfile(info)
            out.write(encryptor.finalize())
            out.write(encryptor.tag)
            out.flush()
            os.fsync(out.fileno())
        # Read back and authenticate before publishing and optional removal.
        confirmed = _verify_portable(tmp, passphrase, key_file)
        if confirmed != writer.hasher.hexdigest():
            raise VaultError('Portable archive verification failed')
        if output.exists() or output.is_symlink():
            raise VaultError('Output appeared during encryption')
        os.rename(tmp, output)
    finally:
        tmp.unlink(missing_ok=True)
    if remove_original:
        try:
            current = source.lstat()
            if (current.st_dev, current.st_ino, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns, current.st_nlink) != (
                orig_stat.st_dev, orig_stat.st_ino, orig_stat.st_size,
                orig_stat.st_mtime_ns, orig_stat.st_ctime_ns, orig_stat.st_nlink):
                raise VaultError('Source changed after encryption; retained')
            source.unlink()
        except (OSError, VaultError) as exc:
            raise VaultError(f'Archive SAVED at {output}; original was retained: {exc}') from exc
    return output


def _open_decryptor(path, passphrase, key_file):
    inp = Path(path).open('rb')
    try:
        lead = inp.read(len(MAGIC) + 4)
        if len(lead) != len(MAGIC) + 4 or not lead.startswith(MAGIC):
            raise VaultError('Not a BlackCube standalone archive')
        n = struct.unpack('>I', lead[len(MAGIC):])[0]
        if not 0 < n <= HEADER_MAX:
            raise VaultError('Invalid portable header')
        raw = inp.read(n)
        if len(raw) != n:
            raise VaultError('Truncated portable header')
        header = json.loads(raw)
        if header.get('v') != 1 or header.get('cipher') not in ('AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM'):
            raise VaultError('Unsupported portable archive')
        if header.get('kdf') != ('Argon2id' if passphrase is not None else 'keyfile-HKDF'):
            raise VaultError('Wrong authentication method for this archive')
        wrap_key = _credential_key(_ub64(header['salt']), passphrase, key_file)
        try:
            file_key = AESGCM(wrap_key).decrypt(_ub64(header['wrap_nonce']),
                        _ub64(header['wrapped']), b'blackcube:portable-key:v1')
        except InvalidTag as exc:
            raise VaultError('Incorrect passphrase/key file or modified archive') from exc
        nonce = _ub64(header['nonce'])
        if len(nonce) != 12 or len(file_key) != 32:
            raise VaultError('Invalid portable encryption parameters')
        start = inp.tell()
        inp.seek(0, os.SEEK_END)
        end = inp.tell()
        if end < start + 16 or end - start - 16 > MAX_TOTAL:
            raise VaultError('Truncated or oversized portable archive')
        inp.seek(end - 16)
        tag = inp.read(16)
        inp.seek(start)
        bits = {'AES-256-GCM': 32, 'AES-192-GCM': 24, 'AES-128-GCM': 16}[header['cipher']]
        dec = Cipher(algorithms.AES(file_key[:bits]), modes.GCM(nonce, tag)).decryptor()
        dec.authenticate_additional_data(lead + raw)
        return inp, dec, end - start - 16
    except BaseException:
        inp.close()
        raise


class _DecryptReader:
    def __init__(self, inp, dec, remaining):
        self.inp, self.dec, self.remaining = inp, dec, remaining
        self.hasher, self.finished = hashlib.sha256(), False

    def read(self, size=-1):
        if size is None or size < 0:
            size = BLOCK
        if size == 0:
            return b''
        if self.remaining == 0:
            self.finish()
            return b''
        data = self.inp.read(min(size, self.remaining))
        if not data:
            raise VaultError('Truncated encrypted archive')
        self.remaining -= len(data)
        plain = self.dec.update(data)
        self.hasher.update(plain)
        return plain

    def finish(self):
        if self.finished:
            return
        while self.remaining:
            self.read(BLOCK)
        try:
            trailer = self.dec.finalize()
        except InvalidTag as exc:
            raise VaultError('Portable archive authentication failed') from exc
        self.hasher.update(trailer)
        self.finished = True


def _verify_portable(path, passphrase, key_file):
    inp, dec, remaining = _open_decryptor(path, passphrase, key_file)
    try:
        reader = _DecryptReader(inp, dec, remaining)
        reader.finish()
        return reader.hasher.hexdigest()
    finally:
        inp.close()


def decrypt_standalone(archive: Path, output_parent: Path, *,
                       passphrase: str | None = None, key_file: Path | None = None) -> Path:
    """Restore one file or folder beside destination; never overwrite data."""
    output_parent = Path(output_parent).resolve()
    if not output_parent.is_dir():
        raise VaultError('Select an existing destination folder')
    archive = Path(archive)
    if archive.is_symlink() or archive.suffix.lower() != '.cubefile':
        raise VaultError('Select a regular .cubefile archive')
    inp, dec, remaining = _open_decryptor(archive, passphrase, key_file)
    stage = output_parent / ('.blackcube-restore-' + uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    try:
        reader = _DecryptReader(inp, dec, remaining)
        count, total, root_name = 0, 0, None
        seen = set()
        with tarfile.open(fileobj=reader, mode='r|') as tar:
            for info in tar:
                count += 1
                if count > MAX_FILES or not (info.isdir() or info.isfile()):
                    raise VaultError('Unsupported or excessive archive entries')
                name = info.name.rstrip('/')
                path = PurePosixPath(name)
                if (not name or path.is_absolute() or '\\' in name or ':' in name
                        or any(x in ('', '.', '..') for x in name.split('/'))):
                    raise VaultError('Unsafe archive member name')
                if root_name is None:
                    root_name = path.parts[0]
                if path.parts[0] != root_name or name in seen:
                    raise VaultError('Multiple roots or duplicate archive entries')
                seen.add(name)
                target = stage.joinpath(*path.parts)
                if info.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    if not 0 <= info.size <= MAX_FILE_BYTES:
                        raise VaultError('Invalid member size')
                    total += info.size
                    if total > MAX_TOTAL:
                        raise VaultError('Archive extraction limit exceeded')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('xb') as out:
                        _ensure_private(target)
                        extracted = tar.extractfile(info)
                        left = info.size
                        while left:
                            chunk = extracted.read(min(left, BLOCK))
                            if not chunk:
                                raise VaultError('Truncated archive member')
                            out.write(chunk)
                            left -= len(chunk)
                        out.flush()
                        os.fsync(out.fileno())
        reader.finish()   # GCM full-tag verification after parsing tar
        if root_name is None:
            raise VaultError('Empty archive')
        published = output_parent / root_name
        if published.exists() or published.is_symlink():
            raise VaultError('Restored file/folder already exists; select another directory')
        os.rename(stage / root_name, published)
        return published
    finally:
        inp.close()
        shutil.rmtree(stage, ignore_errors=True)
