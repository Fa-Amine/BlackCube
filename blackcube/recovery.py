"""Non-destructive verified backups of encrypted vault directories.

The backup ZIP contains encrypted objects and metadata only; it is NOT itself
password encrypted. A keyed MAC covers the manifest and authenticates it for
anyone with an unlocked VaultSession.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from .crypto import VaultError, verify_encrypted_file

MAX_BACKUP_ENTRIES = 100_500
MAX_BACKUP_BYTES = 100 * 1024**3
MAX_MANIFEST_BYTES = 32 * 1024**2
MAX_METADATA_BYTES = 512 * 1024
MAX_INDEX_BYTES = 16 * 1024**2


def _digest_stream(f):
    h = hashlib.sha256()
    while chunk := f.read(1024 * 1024):
        h.update(chunk)
    return h.hexdigest()


def _backup_files(session):
    folder = session.directory
    paths = [folder / 'vault.json', folder / 'state.enc']
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise VaultError('Missing or linked vault metadata file')
    for entry in session.entries:
        if entry['type'] == 'encrypted':
            target = folder / 'objects' / (entry['id'] + '.bcube')
            if target.is_symlink() or not target.is_file():
                raise VaultError('Missing or linked encrypted object: ' + entry['id'])
            digest = verify_encrypted_file(target, session._master, session.vault_id,
                       session._state.get('hybrid_private'), entry['hash_algorithm'])
            if not hmac.compare_digest(digest, entry['digest']):
                raise VaultError('Object failed plaintext digest verification')
            paths.append(target)
    return paths


def create_backup(session, output: Path) -> Path:
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise VaultError('Backup target already exists')
    if output.resolve().is_relative_to(session.directory.resolve()):
        raise VaultError('Cannot put a backup inside the vault')
    files = _backup_files(session)
    if len(files) > MAX_BACKUP_ENTRIES or sum(p.stat().st_size for p in files) > MAX_BACKUP_BYTES:
        raise VaultError('Vault exceeds backup limits')
    tmp = output.with_name('.' + output.name + '.' + uuid.uuid4().hex + '.partial')
    manifest = {'format': 'BlackCube-vault-backup-v1', 'vault_id': session.vault_id,
                'files': {}}
    try:
        with zipfile.ZipFile(tmp, 'x', compression=zipfile.ZIP_STORED, allowZip64=True) as z:
            for path in files:
                name = path.relative_to(session.directory).as_posix()
                with path.open('rb') as f:
                    digest = _digest_stream(f)
                manifest['files'][name] = {'sha256': digest, 'size': path.stat().st_size}
                z.write(path, name)
            canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
            mac = hmac.digest(session._master, b'BlackCube-backup-manifest-v1' + canonical,
                              'sha256').hex()
            z.writestr('manifest.json', json.dumps({'manifest': manifest, 'hmac_sha256': mac}))
        # Windows _commit (used by os.fsync) requires a writable descriptor.
        # The ZIP has already been closed; reopen it read/write only to flush.
        with tmp.open('r+b') as f:
            os.fsync(f.fileno())
        # Validate that the actual completed backup matches the manifest.
        _verify_backup_container(tmp, expected_master=session._master)
        if output.exists() or output.is_symlink():
            raise VaultError('Backup target appeared during creation')
        os.rename(tmp, output)
        return output
    finally:
        tmp.unlink(missing_ok=True)


def _verify_backup_container(source: Path, expected_master: bytes | None = None):
    with zipfile.ZipFile(source, 'r') as z:
        infos = z.infolist()
        if not 3 <= len(infos) <= MAX_BACKUP_ENTRIES or len({x.filename for x in infos}) != len(infos):
            raise VaultError('Invalid backup entries')
        if sum(x.file_size for x in infos) > MAX_BACKUP_BYTES:
            raise VaultError('Backup exceeds safe unpack limits')
        by_name = {info.filename: info for info in infos}
        if ('manifest.json' not in by_name or
            by_name['manifest.json'].file_size > MAX_MANIFEST_BYTES or
            'vault.json' not in by_name or
            by_name['vault.json'].file_size > MAX_METADATA_BYTES or
            'state.enc' not in by_name or
            by_name['state.enc'].file_size > MAX_INDEX_BYTES):
            raise VaultError('Backup metadata is missing or oversized')
        if any(x.is_dir() or x.flag_bits & 1 or x.file_size < 0 for x in infos):
            raise VaultError('Encrypted or invalid ZIP entries are unsupported')
        try:
            details = json.loads(z.read('manifest.json'))
            manifest = details['manifest']
            if manifest['format'] != 'BlackCube-vault-backup-v1':
                raise VaultError('Unsupported backup format')
            paths = manifest['files']
            if set(z.namelist()) != set(paths) | {'manifest.json'}:
                raise VaultError('Backup manifest mismatch')
            if 'vault.json' not in paths or 'state.enc' not in paths:
                raise VaultError('Missing vault metadata')
            if expected_master is not None:
                canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
                expected = hmac.digest(expected_master,
                    b'BlackCube-backup-manifest-v1' + canonical, 'sha256').hex()
                if not hmac.compare_digest(expected, details['hmac_sha256']):
                    raise VaultError('Backup authentication failed')
            for name, entry in paths.items():
                p = PurePosixPath(name)
                if (p.is_absolute() or '\\' in name or ':' in name or
                    '..' in p.parts or name.endswith('/') or len(p.parts) > 2 or
                    (len(p.parts) == 2 and p.parts[0] != 'objects')):
                    raise VaultError('Unsafe backup entry')
                info = z.getinfo(name)
                if info.file_size != entry['size']:
                    raise VaultError('Incorrect backup entry size')
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise VaultError('Backup symlinks are forbidden')
                with z.open(info, 'r') as stream:
                    if not hmac.compare_digest(_digest_stream(stream), entry['sha256']):
                        raise VaultError('Backup checksum mismatch for ' + name)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            raise VaultError('Invalid or damaged backup') from exc
        return manifest


def verify_backup(session, source: Path) -> dict:
    manifest = _verify_backup_container(source, expected_master=session._master)
    if manifest['vault_id'] != session.vault_id:
        raise VaultError('Backup belongs to another vault')
    return manifest


def backup_unlock_mode(source: Path) -> str:
    """Read only the authentication policy from a structurally verified backup."""
    _verify_backup_container(Path(source))
    with zipfile.ZipFile(source) as z:
        try:
            config = json.loads(z.read('vault.json'))
        except (ValueError, TypeError, KeyError) as exc:
            raise VaultError('Invalid backup vault configuration') from exc
    mode = config.get('unlock_mode', 'either')
    if mode not in ('either', 'passphrase', 'keyfile', 'both'):
        raise VaultError('Unknown backup vault authentication policy')
    return mode


def _restore_backup(source: Path, home: Path, *, password: str | None = None,
                    key_file: Path | None = None, verified: bool = False) -> Path:
    """Import to an unpublished staging directory; never overwrite an existing vault.

    In verified mode authentication and all encrypted-object plaintext digests
    are checked inside staging before the restored vault becomes visible.
    """
    source = Path(source)
    manifest = _verify_backup_container(source)
    vid = manifest['vault_id']
    if len(vid) != 32 or any(c not in '0123456789abcdef' for c in vid):
        raise VaultError('Invalid backup vault identifier')
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True)
    dest = home / vid
    if dest.exists() or dest.is_symlink():
        raise VaultError('A vault with this ID already exists; refusing overwrite')
    staging = home / ('.recover-' + uuid.uuid4().hex)
    staging.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(source) as z:
            for name in manifest['files']:
                target = staging.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(name) as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out, length=1024 * 1024)
                    out.flush()
                    os.fsync(out.fileno())
        for name, meta in manifest['files'].items():
            with staging.joinpath(*PurePosixPath(name).parts).open('rb') as f:
                if not hmac.compare_digest(_digest_stream(f), meta['sha256']):
                    raise VaultError('Recovered object digest mismatch')
        if verified:
            from .vault import open_vault
            from .health import check_vault
            try:
                session = open_vault(staging, password=password, key_file=key_file)
            except (OSError, KeyError, TypeError, ValueError, VaultError) as exc:
                raise VaultError('Backup could not be unlocked with supplied credentials') from exc
            if session.vault_id != vid:
                raise VaultError('Recovered vault identifier does not match manifest')
            report = check_vault(session)
            if not report['healthy']:
                raise VaultError('Backup encrypted objects failed authentication: ' +
                                 '; '.join(report['problems'][:3]))
            # MAC authenticates the manifest using the verified vault master key.
            _verify_backup_container(source, expected_master=session._master)
        if dest.exists() or dest.is_symlink():
            raise VaultError('Recovery destination appeared during import')
        os.rename(staging, dest)
        return dest
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def import_backup(source: Path, home: Path) -> Path:
    """Legacy, structurally checked import; use import_verified_backup for safe restore.

    This retains compatibility with previous CLI/tests. Import does NOT
    authenticate the vault against a credential before publishing.
    """
    return _restore_backup(source, home)


def import_verified_backup(source: Path, home: Path, *, password: str | None = None,
                           key_file: Path | None = None) -> Path:
    """Recover only after vault unlock and all encrypted objects authenticate."""
    return _restore_backup(source, home, password=password, key_file=key_file, verified=True)
