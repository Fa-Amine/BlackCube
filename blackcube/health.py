"""Vault object integrity and crash-recovery inventory; no destructive repair."""
from pathlib import Path
import hmac
from .crypto import VaultError, verify_encrypted_file


def check_vault(session) -> dict:
    problems = []
    expected = set()
    encrypted = 0
    for entry in session.entries:
        if entry.get('type') != 'encrypted':
            continue
        encrypted += 1
        name = entry['id'] + '.bcube'
        expected.add(name)
        path = session.directory / 'objects' / name
        try:
            if path.is_symlink() or not path.is_file():
                raise VaultError('Object missing or symlinked')
            got = verify_encrypted_file(path, session._master, session.vault_id,
                   session._state.get('hybrid_private'), entry['hash_algorithm'])
            if not hmac.compare_digest(got, entry['digest']):
                raise VaultError('Object plaintext digest mismatch')
        except (OSError, VaultError, ValueError, KeyError) as exc:
            problems.append(f'{name}: {exc}')
    objects_dir = session.directory / 'objects'
    extra = sorted(p.name for p in objects_dir.iterdir() if p.name.endswith('.bcube')
                   and p.name not in expected)
    staging = session.directory / 'staging'
    pending = sorted(p.name for p in staging.iterdir()) if staging.is_dir() else []
    return {'encrypted_entries': encrypted, 'problems': problems,
            'orphan_objects': extra, 'interrupted_staging': pending,
            'healthy': not problems and not extra and not pending}


def quarantine_uncommitted(session) -> dict:
    """Non-destructively isolate orphan objects and interrupted staging files.

    Never remove a referenced ciphertext or original plaintext. Run only when
    no operation is in progress in ANY BlackCube instance: this helper does not
    yet provide a cross-process vault lock.
    """
    import os
    import uuid
    import json
    from .vault import _write_atomic, now

    directory = session.directory
    report = check_vault(session)
    if report['problems']:
        raise VaultError('Referenced objects failed integrity verification; no automatic repair is safe')
    to_move = []
    for item in report['orphan_objects']:
        source = directory / 'objects' / item
        if source.is_symlink() or not source.is_file():
            raise VaultError('Unexpected linked or missing orphan object')
        to_move.append((source, 'objects', item))
    for item in report['interrupted_staging']:
        source = directory / 'staging' / item
        if source.is_symlink() or not source.is_file():
            raise VaultError('Unexpected linked or missing staging item')
        to_move.append((source, 'staging', item))
    if not to_move:
        return {'quarantine': None, 'items': [], 'healthy': True}
    quarantine = directory / 'quarantine' / ('recovery-' + uuid.uuid4().hex)
    quarantine.mkdir(parents=True, mode=0o700)
    moved = []
    try:
        for src, kind, name in to_move:
            dest = quarantine / kind / name
            dest.parent.mkdir(exist_ok=True)
            os.replace(src, dest)
            moved.append({'source_type': kind, 'name': name})
        _write_atomic(quarantine / 'inventory.json', json.dumps({
            'created': now(), 'reason': 'Uncommitted objects quarantined without deletion',
            'items': moved}, separators=(',', ':')).encode('utf-8'))
    except BaseException:
        # Preserve any already moved objects in quarantine; never delete them.
        raise
    return {'quarantine': str(quarantine), 'items': moved,
            'healthy': check_vault(session)['healthy']}
