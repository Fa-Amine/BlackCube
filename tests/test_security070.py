"""Security regressions for mandatory vault unlock factors and backward compatibility."""
import os
from pathlib import Path
import pytest
from blackcube.crypto import VaultError
from blackcube.vault import create_vault, open_vault

PASSWORD = 'correct-battery-very-long-vault-password'
NEW_PASSWORD = 'another-generously-long-vault-password'


def vault(tmp_path):
    return create_vault('My test vault', PASSWORD, profile=None, home=tmp_path / 'vaults')


def test_legacy_either_unlock_remains_compatible(tmp_path):
    s = vault(tmp_path)
    key = tmp_path / 'legacy.bckey'
    s.add_keyfile(PASSWORD, key)
    assert open_vault(s.directory, password=PASSWORD).name == s.name
    assert open_vault(s.directory, key_file=key).name == s.name


def test_mandatory_dual_factor_prevents_single_factor_bypass(tmp_path):
    s = vault(tmp_path)
    old_key = tmp_path / 'old.bckey'
    s.add_keyfile(PASSWORD, old_key)
    new_key = tmp_path / 'both.bckey'
    s.require_two_factors(PASSWORD, new_key)
    assert new_key.stat().st_size == 32
    assert s.config['unlock_mode'] == 'both'
    assert 'master_wrap' not in s.config and 'keyfile_wrap' not in s.config
    for kwargs in ({'password': PASSWORD}, {'key_file': new_key},
                   {'key_file': old_key}, {'password': PASSWORD, 'key_file': old_key},
                   {'password': 'wrong-passphrase', 'key_file': new_key}):
        with pytest.raises(VaultError):
            open_vault(s.directory, **kwargs)
    reloaded = open_vault(s.directory, password=PASSWORD, key_file=new_key)
    assert reloaded.name == s.name
    with pytest.raises(VaultError):
        s.verify_unlock(password=PASSWORD)
    s.verify_unlock(password=PASSWORD, key_file=new_key)


def test_wrong_key_file_cannot_be_substituted(tmp_path):
    s = vault(tmp_path)
    original = tmp_path / 'correct.bckey'
    s.require_two_factors(PASSWORD, original)
    bogus = tmp_path / 'bogus.bckey'
    bogus.write_bytes(os.urandom(32))
    with pytest.raises(VaultError):
        open_vault(s.directory, password=PASSWORD, key_file=bogus)


def test_generated_key_only_disables_password(tmp_path):
    s = vault(tmp_path)
    generated = tmp_path / 'only.bckey'
    s.require_keyfile_only(PASSWORD, generated)
    assert 'master_wrap' not in s.config
    with pytest.raises(VaultError):
        open_vault(s.directory, password=PASSWORD)
    assert open_vault(s.directory, key_file=generated).name == s.name
    with pytest.raises(VaultError):
        s.change_passphrase(PASSWORD, NEW_PASSWORD)
    s.require_passphrase_only(NEW_PASSWORD, current_key_file=generated)
    with pytest.raises(VaultError):
        open_vault(s.directory, key_file=generated)
    assert open_vault(s.directory, password=NEW_PASSWORD).name == s.name


def test_change_dual_password_requires_key_file(tmp_path):
    s = vault(tmp_path)
    key = tmp_path / 'both.bckey'
    s.require_two_factors(PASSWORD, key)
    with pytest.raises(VaultError):
        s.change_passphrase(PASSWORD, NEW_PASSWORD)
    s.change_passphrase(PASSWORD, NEW_PASSWORD, key_file=key)
    with pytest.raises(VaultError):
        open_vault(s.directory, password=PASSWORD, key_file=key)
    assert open_vault(s.directory, password=NEW_PASSWORD, key_file=key).name == s.name


def test_credential_write_failure_does_not_lock_out_user(tmp_path, monkeypatch):
    import blackcube.vault as mod
    s = vault(tmp_path)
    new_key = tmp_path / 'both.bckey'
    old = (s.directory / 'vault.json').read_bytes()
    original = mod._write_atomic
    def fail_config(path, data):
        if path.name == 'vault.json':
            raise OSError('injected filesystem failure')
        return original(path, data)
    monkeypatch.setattr(mod, '_write_atomic', fail_config)
    with pytest.raises(OSError):
        s.require_two_factors(PASSWORD, new_key)
    assert not new_key.exists()
    assert (s.directory / 'vault.json').read_bytes() == old
    assert open_vault(s.directory, password=PASSWORD).name == s.name


def test_reject_keyfile_stored_in_vault_and_existing_path(tmp_path):
    s = vault(tmp_path)
    with pytest.raises(VaultError):
        s.require_two_factors(PASSWORD, s.directory / 'access.bckey')
    existing = tmp_path / 'existing.bckey'
    existing.write_bytes(os.urandom(32))
    with pytest.raises(VaultError):
        s.require_two_factors(PASSWORD, existing)
    assert open_vault(s.directory, password=PASSWORD).name == s.name


def test_mandatory_key_still_decrypts_ciphertext(tmp_path):
    s = vault(tmp_path)
    source = tmp_path / 'sample.bin'
    source.write_bytes(os.urandom(20012))
    count, warnings = s.import_path(source)
    assert count == 1 and not warnings
    key = tmp_path / 'access.bckey'
    s.require_two_factors(PASSWORD, key)
    reopened = open_vault(s.directory, password=PASSWORD, key_file=key)
    out = tmp_path / 'restored'; out.mkdir()
    restored = reopened.restore(reopened.entries[0]['id'], out)
    assert restored.read_bytes() == source.read_bytes()

@pytest.mark.parametrize('mode', ['passphrase', 'keyfile', 'both'])
def test_backup_verified_before_publish(tmp_path, mode):
    from blackcube.recovery import create_backup, import_verified_backup, backup_unlock_mode
    s = vault(tmp_path)
    source = tmp_path / 'file.txt'; source.write_text('keep this data')
    assert s.import_path(source)[0] == 1
    key = tmp_path / 'access.bckey'
    if mode == 'both':
        s.require_two_factors(PASSWORD, key)
    elif mode == 'keyfile':
        s.require_keyfile_only(PASSWORD, key)
    archive = create_backup(s, tmp_path / 'backup.zip')
    assert backup_unlock_mode(archive) == ('either' if mode == 'passphrase' else mode)
    dest = tmp_path / 'recovered'
    with pytest.raises(VaultError):
        import_verified_backup(archive, dest, password='incorrect-and-very-long',
                               key_file=key if mode == 'both' else None)
    assert not (dest / s.vault_id).exists()
    credentials = ({'password': PASSWORD} if mode == 'passphrase'
                   else {'key_file': key} if mode == 'keyfile'
                   else {'password': PASSWORD, 'key_file': key})
    restored = import_verified_backup(archive, dest, **credentials)
    opened = open_vault(restored, **credentials)
    out = tmp_path / 'output'; out.mkdir()
    assert opened.restore(opened.entries[0]['id'], out).read_text() == source.read_text()


def test_verified_backup_rejects_valid_container_with_inconsistent_object(tmp_path):
    from blackcube.recovery import create_backup, import_verified_backup
    import zipfile, json, hashlib, hmac
    s = vault(tmp_path)
    source = tmp_path / 'source'; source.write_text('verified')
    assert s.import_path(source)[0] == 1
    archive = create_backup(s, tmp_path / 'saved.zip')
    # Valid archive checksums and manifest MAC cannot compensate for tampered AEAD.
    # Deliberately mutate object and recalculate the authenticated manifest
    # (adversarial case: attacker knows master key or local software corruption).
    with zipfile.ZipFile(archive, 'r') as z:
        content = {x.filename: z.read(x.filename) for x in z.infolist()}
    member = next(n for n in content if n.endswith('.bcube'))
    content[member] = content[member][:-1] + bytes([content[member][-1] ^ 1])
    details = json.loads(content['manifest.json'])
    details['manifest']['files'][member]['sha256'] = hashlib.sha256(content[member]).hexdigest()
    payload = json.dumps(details['manifest'], sort_keys=True, separators=(',', ':')).encode()
    details['hmac_sha256'] = hmac.digest(s._master, b'BlackCube-backup-manifest-v1' + payload, 'sha256').hex()
    content['manifest.json'] = json.dumps(details).encode()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
        for name, data in content.items(): z.writestr(name, data)
    with pytest.raises(VaultError):
        import_verified_backup(archive, tmp_path / 'notpublished', password=PASSWORD)
    assert not (tmp_path / 'notpublished' / s.vault_id).exists()


def test_no_keyfile_exposure_after_policy_switch(tmp_path):
    s = vault(tmp_path)
    old_key = tmp_path / 'old.bckey'
    s.add_keyfile(PASSWORD, old_key)
    new_key = tmp_path / 'new.bckey'
    s.require_keyfile_only(PASSWORD, new_key)
    with pytest.raises(VaultError):
        open_vault(s.directory, key_file=old_key)
    assert open_vault(s.directory, key_file=new_key).name == s.name


def test_recovery_moves_uncommitted_only_not_referenced_objects(tmp_path):
    from blackcube.health import quarantine_uncommitted, check_vault
    s = vault(tmp_path)
    source = tmp_path / 'source.txt'; source.write_text('keep me')
    assert s.import_path(source)[0] == 1
    used = s.directory / 'objects' / (s.entries[0]['id'] + '.bcube')
    protected = used.read_bytes()
    staging = s.directory / 'staging'
    staging.mkdir(exist_ok=True)
    (staging / 'aborted.pending').write_bytes(b'garbage but preserve')
    orphan = s.directory / 'objects' / 'orphan.bcube'
    orphan.write_bytes(b'old encrypted data')
    assert not check_vault(s)['healthy']
    result = quarantine_uncommitted(s)
    assert result['healthy']
    q = Path(result['quarantine'])
    assert (q / 'staging' / 'aborted.pending').read_bytes() == b'garbage but preserve'
    assert (q / 'objects' / 'orphan.bcube').read_bytes() == b'old encrypted data'
    assert used.read_bytes() == protected
    assert source.read_text() == 'keep me'
    assert quarantine_uncommitted(s)['quarantine'] is None


def test_recovery_refuses_to_touch_vault_with_broken_referenced_object(tmp_path):
    from blackcube.health import quarantine_uncommitted
    s = vault(tmp_path)
    source = tmp_path / 'file'; source.write_text('important')
    s.import_path(source)
    target = s.directory / 'objects' / (s.entries[0]['id'] + '.bcube')
    target.write_bytes(b'damaged')
    staging = s.directory / 'staging'; staging.mkdir(exist_ok=True)
    pending = staging / 'uncommitted.pending'; pending.write_bytes(b'preserve')
    with pytest.raises(VaultError):
        quarantine_uncommitted(s)
    assert pending.read_bytes() == b'preserve'


def test_two_sessions_cannot_silently_overwrite_index(tmp_path):
    s = vault(tmp_path)
    other = open_vault(s.directory, password=PASSWORD)
    one = tmp_path / 'first'; one.write_bytes(b'first')
    two = tmp_path / 'second'; two.write_bytes(b'second')
    assert s.import_path(one)[0] == 1
    count, warnings = other.import_path(two)
    assert count == 0 and any('another process' in warning for warning in warnings)
    fresh = open_vault(s.directory, password=PASSWORD)
    assert len(fresh.entries) == 1
    out = tmp_path / 'restored'; out.mkdir()
    assert fresh.restore(fresh.entries[0]['id'], out).read_bytes() == b'first'
    assert two.read_bytes() == b'second'


def test_two_sessions_cannot_silently_revert_access_policy(tmp_path):
    s = vault(tmp_path)
    stale = open_vault(s.directory, password=PASSWORD)
    key = tmp_path / 'secret.bckey'
    s.require_two_factors(PASSWORD, key)
    with pytest.raises(VaultError, match='changed in another process'):
        stale.change_passphrase(PASSWORD, NEW_PASSWORD)
    with pytest.raises(VaultError):
        open_vault(s.directory, password=PASSWORD)
    assert open_vault(s.directory, password=PASSWORD, key_file=key).name == s.name


def test_metadata_file_lock_blocks_concurrent_writer(tmp_path):
    from blackcube.vault import _vault_write_lock
    s = vault(tmp_path)
    with _vault_write_lock(s.directory):
        with pytest.raises(VaultError, match='busy'):
            with _vault_write_lock(s.directory, timeout=0.07):
                pass


@pytest.mark.parametrize('filename', ['recovery.bckey', 'backup.cube-key'])
def test_source_removal_cannot_delete_key_material(tmp_path, filename):
    from blackcube.portable import encrypt_standalone
    s = vault(tmp_path)
    sensitive_key = tmp_path / filename
    sensitive_key.write_bytes(os.urandom(32))
    count, warnings = s.import_path(sensitive_key, remove_original=True)
    assert count == 0 and warnings
    assert sensitive_key.exists()
    with pytest.raises(VaultError, match='recovery key'):
        encrypt_standalone(sensitive_key, passphrase=PASSWORD, remove_original=True)
    assert sensitive_key.exists()
