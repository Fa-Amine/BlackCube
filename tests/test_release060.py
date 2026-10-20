"""BlackCube v0.4–0.6 adversarial and recovery regressions."""
import hashlib
import os
import zipfile
from pathlib import Path

import pytest

from blackcube.crypto import VaultError, HASHES
from blackcube.vault import create_vault, open_vault
from blackcube.portable import (encrypt_standalone, decrypt_standalone,
                                 generate_portable_keyfile)
from blackcube.recovery import create_backup, verify_backup, import_backup
from blackcube.health import check_vault

PASS = 'four excellent diceware words and another'


@pytest.mark.parametrize('mode', ['AES-256-GCM','AES-128-GCM','AES-192-GCM','ChaCha20-Poly1305'])
@pytest.mark.parametrize('size', [0, 2049, 1024 * 1024 + 4096])
def test_all_vault_ciphers_legacy_compatible(tmp_path, mode, size):
    s = create_vault('ciphers', PASS, profile=None, home=tmp_path / 'vaults')
    original = tmp_path / 'sample.bin'
    content = os.urandom(size)
    original.write_bytes(content)
    count, problems = s.import_path(original, mode=mode, hash_algorithm='SHA-512')
    assert count == 1 and not problems
    reopened = open_vault(s.directory, PASS)
    destination = tmp_path / 'restored'
    destination.mkdir()
    assert reopened.restore(reopened.entries[0]['id'], destination).read_bytes() == content
    assert reopened.verify_hash(reopened.entries[0]['id'], original)


@pytest.mark.parametrize('mode', ['AES-128-GCM','AES-192-GCM','ChaCha20-Poly1305'])
def test_new_cipher_fails_closed_on_corruption(tmp_path, mode):
    s = create_vault('tamper', PASS, profile=None, home=tmp_path / 'vaults')
    f = tmp_path / 'data.bin'; f.write_bytes(os.urandom(1024 * 1024 + 37))
    assert s.import_path(f, mode=mode)[0] == 1
    obj = s.directory / 'objects' / (s.entries[0]['id'] + '.bcube')
    original = obj.read_bytes()
    for mutation in [original[:-1], original[:-21], original[:-512] + bytes([original[-512]^1]) + original[-511:]]:
        obj.write_bytes(mutation)
        with pytest.raises(VaultError):
            s.restore(s.entries[0]['id'], tmp_path / 'out')
        assert not (tmp_path / 'out' / 'data.bin').exists()
    obj.write_bytes(original)
    assert check_vault(s)['healthy']


def test_hash_choices(tmp_path):
    f = tmp_path / 'data.txt'; f.write_text('hash me')
    s = create_vault('Hashes', PASS, profile=None, home=tmp_path / 'v')
    for algo in HASHES:
        n, warnings = s.import_path(f, hash_only=True, hash_algorithm=algo)
        assert n == 1 and not warnings
        assert s.verify_hash(s.entries[-1]['id'], f)


def test_portable_directory_and_empty_dirs(tmp_path):
    root = tmp_path / 'folder1'
    (root / 'nested').mkdir(parents=True)
    (root / 'empty').mkdir()
    (root / 'nested' / 'f-é.txt').write_bytes(os.urandom(2 * 1024 * 1024 + 17))
    archive = encrypt_standalone(root, passphrase=PASS)
    assert archive == tmp_path / 'folder1.cubefile'
    assert root.exists()
    dest = tmp_path / 'restored'; dest.mkdir()
    result = decrypt_standalone(archive, dest, passphrase=PASS)
    assert (result / 'nested' / 'f-é.txt').read_bytes() == (root / 'nested' / 'f-é.txt').read_bytes()
    assert (result / 'empty').is_dir()
    with pytest.raises(VaultError, match='already exists'):
        decrypt_standalone(archive, dest, passphrase=PASS)


def test_portable_file_remove_after_authenticated_readback(tmp_path):
    source = tmp_path / 'private.pdf'; contents = os.urandom(23456)
    source.write_bytes(contents)
    archive = encrypt_standalone(source, passphrase=PASS, remove_original=True)
    assert archive.exists() and not source.exists()
    out = tmp_path / 'destination'; out.mkdir()
    assert decrypt_standalone(archive, out, passphrase=PASS).read_bytes() == contents


def test_portable_keyfiles_and_wrong_credential(tmp_path):
    f = tmp_path / 'key.cube-key'
    generate_portable_keyfile(f)
    source = tmp_path / 'notes.txt'; source.write_text('secret')
    archive = encrypt_standalone(source, key_file=f)
    with pytest.raises(VaultError):
        decrypt_standalone(archive, tmp_path, passphrase=PASS)
    wrong = tmp_path / 'wrong.key'; wrong.write_bytes(os.urandom(32))
    with pytest.raises(VaultError):
        decrypt_standalone(archive, tmp_path, key_file=wrong)
    restored = tmp_path / 'restore'; restored.mkdir()
    assert decrypt_standalone(archive, restored, key_file=f).read_text() == 'secret'
    with pytest.raises(VaultError):
        generate_portable_keyfile(f)


@pytest.mark.parametrize('change', ['tag','payload','truncate','header'])
def test_portable_corruption_leaves_no_published_files(tmp_path, change):
    source = tmp_path / 'secret.txt'; source.write_text('top secret')
    archive = encrypt_standalone(source, passphrase=PASS)
    data = bytearray(archive.read_bytes())
    if change == 'tag': data[-1] ^= 1
    if change == 'payload': data[-110] ^= 1
    if change == 'header': data[16] ^= 1
    if change == 'truncate': data = data[:-50]
    archive.write_bytes(data)
    output = tmp_path / 'restore'; output.mkdir()
    with pytest.raises((VaultError, ValueError)):
        decrypt_standalone(archive, output, passphrase=PASS)
    assert list(output.iterdir()) == []


def test_portable_folder_removal_not_implemented_without_transaction(tmp_path):
    folder = tmp_path / 'folder'; folder.mkdir()
    (folder / 'data.txt').write_text('do not lose')
    with pytest.raises(VaultError, match='Folder deletion'):
        encrypt_standalone(folder, passphrase=PASS, remove_original=True)
    assert (folder / 'data.txt').read_text() == 'do not lose'


def test_backup_and_import_then_restore(tmp_path):
    s = create_vault('test', PASS, profile=None, home=tmp_path / 'vaults')
    f = tmp_path / 'file.bin'; f.write_bytes(os.urandom(21000))
    s.import_path(f, mode='ChaCha20-Poly1305')
    archive = create_backup(s, tmp_path / 'snapshot.zip')
    assert verify_backup(s, archive)['vault_id'] == s.vault_id
    with pytest.raises(VaultError):
        import_backup(archive, tmp_path / 'vaults')
    recovered = import_backup(archive, tmp_path / 'recovered')
    second = open_vault(recovered, PASS)
    result_dir = tmp_path / 'unpacked'; result_dir.mkdir()
    assert second.restore(second.entries[0]['id'], result_dir).read_bytes() == f.read_bytes()
    with pytest.raises(VaultError):
        import_backup(archive, tmp_path / 'recovered')


def test_backup_detects_mutation(tmp_path):
    s = create_vault('test', PASS, profile=None, home=tmp_path / 'vaults')
    f = tmp_path / 'file.bin'; f.write_bytes(b'hello')
    s.import_path(f)
    archive = create_backup(s, tmp_path / 'snapshot.zip')
    with zipfile.ZipFile(archive, 'r') as z:
        contents = {entry.filename: z.read(entry.filename) for entry in z.infolist()}
    name = next(x for x in contents if x.endswith('.bcube'))
    contents[name] = contents[name][:-1] + bytes([contents[name][-1]^1])
    with zipfile.ZipFile(archive, 'w') as z:
        for name, b in contents.items():
            z.writestr(name, b)
    with pytest.raises(VaultError):
        verify_backup(s, archive)
    with pytest.raises(VaultError):
        import_backup(archive, tmp_path / 'target')


def test_health_report_interrupted_staging_and_orphan(tmp_path):
    s = create_vault('health', PASS, profile=None, home=tmp_path / 'vaults')
    f = tmp_path / 'f'; f.write_text('hello')
    s.import_path(f)
    report = check_vault(s)
    assert report['healthy']
    (s.directory / 'staging').mkdir(exist_ok=True)
    (s.directory / 'staging' / 'dead.pending').write_bytes(b'x')
    (s.directory / 'objects' / 'orphan.bcube').write_bytes(b'y')
    report = check_vault(s)
    assert not report['healthy'] and 'dead.pending' in report['interrupted_staging']
    assert 'orphan.bcube' in report['orphan_objects']


def test_keyfile_credential_replace_and_disable(tmp_path):
    s = create_vault('key', PASS, profile=None, home=tmp_path / 'vaults')
    old = tmp_path / 'old.bckey'; s.add_keyfile(PASS, old)
    new = tmp_path / 'new.bckey'; s.replace_keyfile(PASS, new)
    with pytest.raises(VaultError):
        open_vault(s.directory, key_file=old)
    assert open_vault(s.directory, key_file=new).name == 'key'
    s.disable_keyfile(PASS)
    with pytest.raises(VaultError):
        open_vault(s.directory, key_file=new)
    assert open_vault(s.directory, password=PASS).name == 'key'


@pytest.mark.parametrize('mode', ['AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM'])
def test_standalone_aes_modes(tmp_path, mode):
    src = tmp_path / 'test.bin'
    src.write_bytes(os.urandom(25000))
    archive = encrypt_standalone(src, passphrase=PASS, cipher=mode)
    out = tmp_path / 'output'; out.mkdir()
    assert decrypt_standalone(archive, out, passphrase=PASS).read_bytes() == src.read_bytes()


def test_backup_archive_sync_opens_writable_handle(tmp_path, monkeypatch):
    """Regression: Windows os.fsync/_commit rejects read-only file descriptors."""
    original_open = Path.open
    sync_modes = []

    def tracked_open(self, mode='r', *args, **kwargs):
        if self.name.endswith('.partial'):
            sync_modes.append(mode)
        return original_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', tracked_open)
    session = create_vault('sync regression', PASS, profile=None, home=tmp_path / 'vaults')
    source = tmp_path / 'file.bin'
    source.write_bytes(b'test data')
    assert session.import_path(source)[0] == 1
    archive = create_backup(session, tmp_path / 'backup.zip')
    assert archive.exists()
    assert 'r+b' in sync_modes, 'Backup fsync must use a writable handle for Windows'
    assert verify_backup(session, archive)['vault_id'] == session.vault_id
