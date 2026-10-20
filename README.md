# BlackCube v0.7.0 Alpha 1 — Vault access and recovery hardening

BlackCube is experimental Windows desktop encryption software written in Python and PySide6. **Not production audited. Do not use as the only copy of sensitive or irreplaceable files.** Existing v0.6 encrypted file objects, vault configuration and standalone `.cubefile` archives remain readable (no format migration).

## Windows installation and upgrade

1. **Back up** your existing entire vault folders, and make sure you can restore a test file before updating. Keep key files separately.
2. Close all running BlackCube windows, including background processes.
3. Extract this source ZIP to a **new application folder**. Do not extract on top of any vault data. You can keep your old source folder until verified.
4. Run `setup_windows.bat` (creates an isolated `.venv`, installs dependencies, runs tests). Then `launch_windows.bat`.
5. Unlock the old vault via Vaults > select existing. The vault directory and ciphertext formats are unchanged.
6. Test adding a **disposable** file, restoring it, creating and importing a backup to a separate empty location.

**Important:** 79 tests passed in the Linux build environment and 8 skipped because PySide6/ML-KEM were unavailable. Windows GUI, Windows-only lock behavior, and ML-KEM still require real Windows validation. If setup tests fail, do not trust the build.

## New: three required unlock policies

| Policy | Can passphrase unlock alone? | Can generated key file unlock alone? | Needed to unlock |
|---|---|---|---|
| Legacy either-factor (v0.6 vaults) | Yes | Yes, if configured | Either one |
| Passphrase only | Yes | No | Passphrase |
| Generated key file only | No | Yes | `.bckey` file |
| Passphrase + generated key file | No | No | **Both together** |

In BlackCube > Settings > Secure access, choose **Require passphrase + generated key file** or **Require generated key file only**, and pick where to save the generated `.bckey`. The generated file contains **32 random bytes (256-bit entropy)**. Never put it inside the encrypted vault. For two-factor mode, the passphrase is processed with Argon2id, the file secret is derived using HKDF, and both contributions are combined with HKDF-SHA256 to wrap the existing 256-bit master key via AES-256-GCM. Only the combined wrap is retained in the live configuration.

**Do not lose the only key file.** In key-file-only mode its loss means permanent lockout if you have no valid backup of the key material. In two-factor mode either lost factor means lockout. Keep *two safely separated offline backups* of generated key files, physically protected, and verify that each can unlock a test vault before deleting or changing anything.

Settings also offers **Switch to passphrase-only access**, requiring the presently configured factors and a newly chosen passphrase. Changing the passphrase in two-factor mode requires the existing key file. Legacy alternate key-file creation/replacement remains supported in legacy either-factor mode. This version does **not** yet rotate a mandatory key file in place; to replace it, switch to passphrase-only, then generate a new mandatory key file (keep the current vault unlocked while doing so).

**Old backups remain decryptable with the credentials that protected them at the time.** Changing an unlock policy is not full master-key rotation and cannot revoke keys embedded in stolen historical vault snapshots.

## Additional v0.7 improvements

- **Cross-process metadata locking**, on Windows (`msvcrt`) and POSIX (`fcntl`): metadata commits serialize and refuse to overwrite files changed by another instance. If you see a stale-state error, lock/reopen the vault. Do not keep multiple windows open during recovery or backups.
- **Authenticated backup import** in GUI and CLI: after structural checks, the archive is unpacked into a private temporary directory; the supplied passphrase/key file unlocks the temporary vault, every encrypted object is decrypted and digest-checked, and the HMAC-protected manifest is checked **before the vault is published**. Failed imports remove the unpublished staging directory, not an existing vault. The older `import_backup` Python API remains available for backward compatibility but is NOT authenticated before publication—use `import_verified_backup`.
- **Interrupted import quarantine:** Settings > Crash recovery moves orphan `.bcube` objects and leftover `.pending` staging files to a vault-local `quarantine/` directory without deleting any bytes. Only use with all other BlackCube instances closed. This is a non-destructive aid, not an automatic resume or complete crash-consistency guarantee.
- **Windows workstation notification hook:** when supported by the system, Windows lock/disconnect/suspend queues an application lock. Active encrypted-file operations finish before the vault locks; the OS session itself should be locked while operations finish.
- Generated key files (`.bckey`, `.cube-key`) cannot be selected for plaintext-source deletion.

## Examples: CLI

From PowerShell inside the extracted folder:

```powershell
.\.venv\Scripts\python.exe -m blackcube.cli list
.\.venv\Scripts\python.exe -m blackcube.cli access-dual <vault-id-prefix> D:\SecureKeys\my-vault.bckey
.\.venv\Scripts\python.exe -m blackcube.cli --help
.\.venv\Scripts\python.exe -m pytest -q
```

To unlock the stricter policy in CLI commands, supply `--key-file D:\SecureKeys\my-vault.bckey`; the program prompts for your passphrase whenever the policy requires it. `backup-import` now requires authenticating the backup before restoring it. The `access-keyfile` and `access-passphrase` CLI commands handle the other two explicit policies. Use `recover-staging` only with all other BlackCube processes closed.

## Main application code

- `blackcube/vault.py` — master key wraps, generated key files, enforced unlock policy, Argon2id+HKDF, optimistic metadata versions, cross-process writes, vault encryption and accounts.
- `blackcube/crypto.py` — streaming authenticated file encryption, SHA family and BLAKE2 hashing, existing ML-KEM hybrid design.
- `blackcube/recovery.py` — backups, authentication before publishing recovered vaults.
- `blackcube/health.py` — integrity health and safe quarantine.
- `blackcube/portable.py` — standalone same-directory `.cubefile` encryption (unchanged format).
- `blackcube/app.py` — Qt GUI: vault selectors, Files, Standalone, Accounts, Integrity and Settings.
- `blackcube/cli.py` — CLI equivalents for tested operations.
- `tests/test_security070.py` — recovery, concurrent updates, mandatory authentication and filesystem failure regressions.

## Boundaries and warnings

This is not yet a production release. There has been **no independent cryptographic audit**. The ML-KEM implementation and Windows UI need Windows end-to-end testing; there is no proven complete crash/power-loss durability, no anti-rollback trust anchor, no full master-key re-encryption, no Windows Hello/TPM, no hardened Windows NTFS DACL setup for every custom location, no native secret-memory guarantee, and no signed EXE/installer. Using a key file on a USB stick does not make it tamper-proof. Windows malware or an unlocked session can still read files or memory. Source removal is standard deletion, not forensic secure erasure.

Read `SECURITY.md` before experimenting with sensitive files. Keep **independently verified offline backups** and retain original plaintext copies during testing.
