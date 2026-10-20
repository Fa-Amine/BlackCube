from pathlib import Path
import pytest

from blackcube.crypto import VaultError
from blackcube.vault import (create_vault, generate_password, list_vault_dirs,
                             open_vault, _safe_relative)

PASSWORD = "correct horse battery staple 2026"


def test_classical_file_roundtrip_integrity_and_accounts(tmp_path):
    store = tmp_path / "vaults"
    s = create_vault("Research black box", PASSWORD, profile=None, home=store)
    assert len(list_vault_dirs(store)) == 1
    assert "Research black box" not in (s.directory / "state.enc").read_bytes().decode("latin1")
    src = tmp_path / "picture.dat"
    data = (b"This is private.\x00\xff" * 170_000) + b"end"
    src.write_bytes(data)
    count, warnings = s.import_path(src)
    assert (count, warnings) == (1, [])
    entry = s.entries[0]
    assert entry["path"] == src.name
    assert entry["type"] == "encrypted"
    obj = s.directory / "objects" / (entry["id"] + ".bcube")
    assert obj.is_file()
    assert b"picture.dat" not in obj.read_bytes()
    assert b"This is private." not in obj.read_bytes()
    assert src.read_bytes() == data  # source not modified
    s.save_account("Mail", "alice@example.com", "correct-password-123", "https://example.com")
    assert "alice@example.com" not in (s.directory / "state.enc").read_bytes().decode("latin1")
    with pytest.raises(VaultError, match="Incorrect"):
        open_vault(s.directory, "wrong passphrase")
    unlocked = open_vault(s.directory, PASSWORD)
    assert unlocked.name == "Research black box"
    assert unlocked.accounts[0]["password"] == "correct-password-123"
    output = tmp_path / "restored"
    output.mkdir()
    restored = unlocked.restore(entry["id"], output)
    assert restored.read_bytes() == data
    assert unlocked.verify_hash(entry["id"], src)
    with pytest.raises(VaultError, match="already exists"):
        unlocked.restore(entry["id"], output)


def test_reject_tampering_without_publishing_plaintext(tmp_path):
    s = create_vault("Tamper", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "a.txt"
    src.write_text("Strictly secret")
    s.import_path(src)
    obj = s.directory / "objects" / (s.entries[0]["id"] + ".bcube")
    raw = bytearray(obj.read_bytes())
    raw[-17] ^= 8  # authenticated ciphertext byte (not the tag)
    obj.write_bytes(raw)
    output = tmp_path / "restore"
    output.mkdir()
    with pytest.raises(VaultError, match="Authentication failed"):
        s.restore(s.entries[0]["id"], output)
    assert list(output.iterdir()) == []


def test_hash_only_does_not_copy_data(tmp_path):
    s = create_vault("Checksums", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "notes.txt"
    src.write_text("hello")
    count, errors = s.import_path(src, hash_only=True, hash_algorithm="SHA3-256")
    assert count == 1 and not errors
    entry = s.entries[0]
    assert entry["type"] == "hash"
    assert list((s.directory / "objects").iterdir()) == []
    assert s.verify_hash(entry["id"], src)
    src.write_text("changed")
    assert not s.verify_hash(entry["id"], src)
    with pytest.raises(VaultError, match="contains no recoverable"):
        s.restore(entry["id"], tmp_path)


def test_folder_and_symlinks(tmp_path):
    s = create_vault("Folder", PASSWORD, profile=None, home=tmp_path / "vaults")
    source = tmp_path / "tree"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "child.txt").write_text("child")
    (source / "top.txt").write_text("top")
    symlink = source / "skip.txt"
    try:
        symlink.symlink_to(source / "top.txt")
    except (OSError, NotImplementedError):
        pass
    count, warnings = s.import_path(source)
    assert count == 2
    assert len(warnings) == (1 if symlink.is_symlink() else 0)
    output = tmp_path / "out"
    output.mkdir()
    for e in s.entries:
        s.restore(e["id"], output)
    assert (output / "tree" / "nested" / "child.txt").read_text() == "child"


def test_change_passphrase_and_account_delete(tmp_path):
    s = create_vault("Rotate", PASSWORD, profile=None, home=tmp_path / "vaults")
    account_id = s.save_account("Service", "user", generate_password())
    s.change_passphrase(PASSWORD, "new correct horse battery staple")
    with pytest.raises(VaultError, match="Incorrect"):
        open_vault(s.directory, PASSWORD)
    unlocked = open_vault(s.directory, "new correct horse battery staple")
    assert unlocked.accounts[0]["id"] == account_id
    unlocked.delete_account(account_id)
    assert open_vault(s.directory, "new correct horse battery staple").accounts == []


@pytest.mark.parametrize("bad", ["../escape", "/absolute", "foo/../../x", "C:/windows", "foo\\bar"])
def test_unsafe_restore_paths_blocked(bad):
    with pytest.raises(VaultError):
        _safe_relative(bad)


def test_hybrid_roundtrip_when_library_available(tmp_path):
    pytest.importorskip("pqcrypto.kem.ml_kem_768")
    s = create_vault("Hybrid", PASSWORD, profile="ML-KEM-768", home=tmp_path / "vaults")
    src = tmp_path / "secret.bin"
    src.write_bytes(b"quantum-safe-ish content" * 10000)
    n, errors = s.import_path(src, mode="Hybrid ML-KEM-768")
    assert n == 1 and not errors
    out = tmp_path / "out"
    out.mkdir()
    fresh = open_vault(s.directory, PASSWORD)
    restored = fresh.restore(fresh.entries[0]["id"], out)
    assert restored.read_bytes() == src.read_bytes()


def test_mutated_public_profile_is_rejected(tmp_path):
    import json
    s = create_vault("Config protected", PASSWORD, profile=None, home=tmp_path / "v")
    metadata = s.directory / "vault.json"
    config = json.loads(metadata.read_text())
    config["profile"] = "ML-KEM-1024"
    metadata.write_text(json.dumps(config))
    with pytest.raises(VaultError, match="modified"):
        open_vault(s.directory, PASSWORD)


@pytest.mark.parametrize("profile", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_all_hybrid_profiles_when_available(tmp_path, profile):
    pytest.importorskip("pqcrypto.kem." + profile.lower().replace("-", "_"))
    s = create_vault("Hybrid matrix", PASSWORD, profile=profile, home=tmp_path / "vaults")
    src = tmp_path / "secret.txt"
    src.write_text("hybrid scheme test" * 100)
    count, warnings = s.import_path(src, mode="Hybrid " + profile)
    assert (count, warnings) == (1, [])
    output = tmp_path / "output"
    output.mkdir()
    restored = open_vault(s.directory, PASSWORD).restore(s.entries[0]["id"], output)
    assert restored.read_bytes() == src.read_bytes()


def test_move_into_vault_requires_verification_then_deletes_original(tmp_path):
    from blackcube.crypto import verify_encrypted_file
    s = create_vault("Deletable", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "confidential.txt"
    content = b"confidential contents!" * 100_000
    src.write_bytes(content)
    count, problems = s.import_path(src, remove_original=True)
    assert (count, problems) == (1, [])
    assert not src.exists()
    assert s.entries[0]["source_removed"] is True
    obj = s.directory / "objects" / (s.entries[0]["id"] + ".bcube")
    assert verify_encrypted_file(obj, s._master, s.vault_id, None) == s.entries[0]["digest"]
    restored_root = tmp_path / "restore"
    restored_root.mkdir()
    restored = open_vault(s.directory, PASSWORD).restore(s.entries[0]["id"], restored_root)
    assert restored.read_bytes() == content


def test_verified_readback_failure_leaves_original(monkeypatch, tmp_path):
    from blackcube import vault as module
    s = create_vault("Hold originals", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "must-stay.bin"
    src.write_bytes(b"data to preserve")
    def fail(*args, **kwargs):
        raise VaultError("Simulated authenticated readback failure")
    monkeypatch.setattr(module, "verify_encrypted_file", fail)
    count, problems = s.import_path(src, remove_original=True)
    assert count == 0
    assert len(problems) == 1
    assert src.read_bytes() == b"data to preserve"
    assert len(open_vault(s.directory, PASSWORD).entries) == 0


def test_changed_source_during_import_retained(monkeypatch, tmp_path):
    from blackcube import vault as module
    s = create_vault("Modifications", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "data.bin"
    src.write_bytes(b"old")
    real_verify = module.verify_encrypted_file
    def tamper_after_encryption(*args, **kwargs):
        result = real_verify(*args, **kwargs)
        src.write_bytes(b"new data")
        return result
    monkeypatch.setattr(module, "verify_encrypted_file", tamper_after_encryption)
    count, problems = s.import_path(src, remove_original=True)
    assert count == 1 and problems
    assert src.read_bytes() == b"new data"


def test_key_file_alternate_unlock_and_reauth(tmp_path):
    store = tmp_path / "vaults"
    s = create_vault("Keyfile", PASSWORD, profile=None, home=store)
    keyfile = tmp_path / "offline-backup.bckey"
    s.add_keyfile(PASSWORD, keyfile)
    assert len(keyfile.read_bytes()) == 32
    assert open_vault(s.directory, key_file=keyfile).vault_id == s.vault_id
    assert open_vault(s.directory, PASSWORD).vault_id == s.vault_id
    fresh = open_vault(s.directory, key_file=keyfile)
    fresh.verify_unlock(key_file=keyfile)
    fresh.verify_unlock(password=PASSWORD)
    with pytest.raises(VaultError):
        fresh.verify_unlock(password="bad passphrase")
    broken = tmp_path / "broken.bckey"
    broken.write_bytes(b"a" * 32)
    with pytest.raises(VaultError):
        open_vault(s.directory, key_file=broken)
    with pytest.raises(VaultError):
        s.add_keyfile(PASSWORD, tmp_path / "second.bckey")
    assert not (tmp_path / "second.bckey").exists()


def test_keyfile_rejected_inside_vault_and_not_overwritten(tmp_path):
    s = create_vault("Keyfile safe", PASSWORD, profile=None, home=tmp_path / "vaults")
    with pytest.raises(VaultError):
        s.add_keyfile(PASSWORD, s.directory / "self.bckey")
    existing = tmp_path / "important.data"
    existing.write_bytes(b"unchanged")
    with pytest.raises(VaultError):
        s.add_keyfile(PASSWORD, existing)
    assert existing.read_bytes() == b"unchanged"


def test_hash_only_never_deletes_original(tmp_path):
    s = create_vault("Hash safety", PASSWORD, profile=None, home=tmp_path / "v")
    src = tmp_path / "original.txt"
    src.write_text("must remain")
    with pytest.raises(VaultError):
        s.import_path(src, hash_only=True, remove_original=True)
    assert src.read_text() == "must remain"


def test_multiple_file_picker_backend(tmp_path):
    s = create_vault("Multi-select", PASSWORD, profile=None, home=tmp_path / "v")
    sources = [tmp_path / f"part{i}.txt" for i in range(3)]
    for src in sources:
        src.write_text(src.name)
    total, errors = s.import_files(sources)
    assert total == 3 and not errors
    assert len(s.entries) == 3
    assert all(src.exists() for src in sources)


def test_recovery_key_file_never_auto_deleted(tmp_path):
    s = create_vault("Protected recovery", PASSWORD, profile=None, home=tmp_path / "vaults")
    key = tmp_path / "keep.bckey"
    s.add_keyfile(PASSWORD, key)
    n, errors = s.import_path(key, remove_original=True)
    assert n == 0 and errors and key.exists()
    assert open_vault(s.directory, key_file=key).vault_id == s.vault_id


def test_keyfile_still_unlocks_after_passphrase_change(tmp_path):
    s = create_vault("Change with recovery", PASSWORD, profile=None, home=tmp_path / "vaults")
    key = tmp_path / "recovery.bckey"
    s.add_keyfile(PASSWORD, key)
    s.change_passphrase(PASSWORD, "new-password-here-123456")
    with pytest.raises(VaultError):
        open_vault(s.directory, PASSWORD)
    assert open_vault(s.directory, key_file=key).vault_id == s.vault_id


def test_readback_corruption_prevents_original_removal(monkeypatch, tmp_path):
    from blackcube import vault as module
    s = create_vault("Corrupted", PASSWORD, profile=None, home=tmp_path / "vaults")
    src = tmp_path / "important.bin"
    src.write_bytes(b"Do not lose this" * 2000)
    original_verify = module.verify_encrypted_file
    def corrupt_then_verify(path, *args, **kwargs):
        raw = bytearray(path.read_bytes())
        raw[-18] ^= 1
        path.write_bytes(raw)
        return original_verify(path, *args, **kwargs)
    monkeypatch.setattr(module, "verify_encrypted_file", corrupt_then_verify)
    n, warnings = s.import_path(src, remove_original=True)
    assert n == 0 and warnings
    assert src.is_file()
    assert src.read_bytes() == b"Do not lose this" * 2000
