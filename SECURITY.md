# BlackCube 0.7.0a1 — Security review status

**Classification: experimental alpha; not production-ready, not security certified, and not independently audited.** Tests running successfully on Linux do not validate Windows UI or ML-KEM behavior. All Windows security claims remain pending Windows verification.

## Model

- Offline, local-first vaults with encrypted index and per-file encrypted objects.
- File ciphertext authenticated with AES-GCM, ChaCha20-Poly1305 or existing ML-KEM hybrid envelopes, according to user selection.
- Master passphrase Argon2id; generated `.bckey` is exactly 32 OS-random bytes, treated as a bearer credential.
- Legacy vaults keep passphrase OR key-file unlock; new explicit policy can require passphrase only, key-file only or BOTH. Both-factor policies remove single-factor wrappers from the current `vault.json`.
- Key wrapping in strict dual mode: 32-byte Argon2id secret + 32-byte HKDF-derived key-file secret -> HKDF-SHA256 (domain-separated, 32-byte random salt) -> AES-256-GCM wrapping the same vault master key.
- Changing the unlock policy does **not** rotate the underlying master key or encrypt/decrypt all existing file objects. It cannot protect older captured snapshots, config backups or keys after the fact. Credential revocation is only against current live config.

## Threat boundaries

- Security of passphrases and key files is the user’s responsibility; do not store key files with encrypted vault backups or in uncontrolled cloud folders. Generated key files have no passphrase themselves. NTFS ACLs for newly created key files inherit directory permissions on Windows, which may be overly broad on some drives. Windows BitLocker/device encryption recommended on supported systems.
- Python-managed master keys, account passwords and file keys may remain in process memory until garbage collected. Locking does not guarantee memory zeroization. A malicious process or compromised OS can extract plaintext during unlocked sessions.
- Clipboard history, swap/pagefile, backups, shadow copies, downloaded documents, Windows Search and cloud sync may preserve plaintext. Delete-source operation performs an unlink, **not** secure erase.
- Stale-state and cross-process write locks protect metadata updates, but are not a database transaction journal; data changes can still be interrupted. Quarantine is non-destructive and does not prove crash recovery for every sequence.
- There is no counter/remote trust anchor to detect rollback of a full old `vault.json` + `state.enc` snapshot. Rotating key wrappers does not revoke already stolen historical snapshots.
- ZIP backup import performs content checks before publication, but is not a substitute for independent backup media or restoration testing.
- External-security review of ML-KEM + X25519 + HKDF hybrid composition, archive parsers, filesystem symlink/hard-link races, and Windows packaging is outstanding.
- Windows workstation lock integration is best effort; confirm on the actual OS. There is no Windows Hello/TPM support yet.

## Release blockers still open

1. Full, authenticated, restartable **master-key rotation and migration** for all file objects and password records.
2. Durable journal/transactions with power-loss injection testing of every stage, Windows volume semantics, and backup/restore across fresh installs.
3. Windows integration: strict data/key-file DACLs, UI/worker test coverage, Windows Hello optional flow, session locking, crash dumps, secure clipboard policy.
4. Cryptographic KATs and fuzz/property-based testing of AEAD, ML-KEM and hybrid protocol; independent security assessment and remediation.
5. Signed deterministic/reproducible Windows binary builds, dependency pinning/SBOM/vulnerability management, signing and release process.

Never rely on this alpha as the sole place for important secrets. Report vulnerabilities privately; never share actual vault files, passwords, key files, private keys, or unredacted logs.
