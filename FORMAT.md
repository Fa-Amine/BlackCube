# BlackCube on-disk encryption format overview (beta; not a formal standard)

## Backward-compatible vault objects

`BCUBE1\x00` header stores a length-prefixed JSON envelope followed by streaming AES-256-GCM ciphertext and a final 16-byte tag. The entire prefix is associated data. The envelope includes a random per-file key wrapping record, vault ID, and ciphertext nonce. Existing v0.3.0 `.bcube` files are still decrypted using that original reader.

`BCUBE2\x00` uses: length-prefixed JSON header, `nonce_prefix` (8 bytes), a per-file random 32-byte key, cipher name, and existing wrapping mode (vault AES-GCM or hybrid ML-KEM/X25519). Every record is `uint32_be(plaintext_length) || AEAD(ciphertext, tag)` (maximum 1 MiB per record); the 12-byte nonce is the 8-byte random prefix concatenated with a big-endian 32-bit record number. Each record is bound to the entire header, 64-bit record sequence number, and 32-bit length by associated data. A length-zero authenticated final record is required. The decoder rejects missing records, extra trailing bytes, wrong tags, record rearrangement, and malformed headers. The 32-byte file key is used for ChaCha20-Poly1305; AES-128/192 use the first 16/24 bytes. Do not mix with the v1 AES-256-GCM stream without explicit version checks.

**Caution:** No external audit has validated this format, hybrid key combiner, or key lifecycle. GCM data-size ceilings and key/nonce uniqueness constraints must be checked before a production release.

## Portable `.cubefile`

`CUBEFILE1\x00` followed by a 32-bit big-endian JSON header length, an authenticated JSON key wrapper (salt, Argon2id vs raw-key-file KDF, wrapped random file key, AES nonce), encrypted TAR stream, then a 16-byte AES-GCM tag. AES-GCM authenticates the entire prefix as associated data. The TAR is generated directly into the streaming cipher without a plaintext intermediary archive. Only regular files and directories are accepted; symbolic links, hardlinks, and other entry types are rejected by the import path. Restores check archive member paths and refuse overwrites, stage recovered plaintext in a randomly named temporary directory, and publish it only after tag verification.

A `.cubefile` archive is **independent of any vault and is NOT equivalent to `.bcube`**, which cannot be decrypted without vault key material. Key files for `.cubefile` and `.bckey` vault recovery are not interchangeable.

## Encrypted vault backups

Backup ZIP members are `vault.json`, `state.enc`, and referenced `objects/*.bcube`; an unencrypted `manifest.json` contains byte sizes, SHA-256 checksums and an HMAC with the vault master key for post-unlock authentication. The ZIP itself is NOT additionally encrypted, because referenced objects and the state index are already encrypted. Its metadata and existence are visible. Recovery writes to a new vault UUID directory without overwriting existing vaults, and file digests are verified before publication.


## v0.7 access policy extension (backward-compatible)

`vault.json` retains `version: 1`. Absent `unlock_mode` means legacy `either`: one of passphrase `master_wrap` or optional `keyfile_wrap` (not both simultaneously). New configurations may set `unlock_mode: "passphrase"`, `"keyfile"`, or `"both"`. Only the required wrapper is persisted for newly enforced policies. The `"both"` mode stores a `dual_wrap` object `{salt, nonce, ciphertext}`; its AES-256-GCM key is HKDF-SHA256 with a random 32-byte salt and info `BlackCube-v2-password-and-keyfile:` concatenated with the raw vault ID, derived from Argon2id(master passphrase) || HKDF(key file, vault ID). All wrappers use the existing master-key AAD. Generated `.bckey` credentials remain 32 raw OS-random bytes for compatibility. Password KDF metadata remains in the config even for keyfile-only mode.

A policy switch does NOT re-encrypt `state.enc` or file objects or revoke old stolen copies.
