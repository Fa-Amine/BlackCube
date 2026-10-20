"""Headless CLI useful for automation and testing. Secrets read via getpass."""
from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from .crypto import PROFILES, VaultError, HASHES
from .vault import create_vault, open_vault, list_vault_dirs, default_home, _read_config
from .portable import encrypt_standalone, decrypt_standalone, generate_portable_keyfile
from .recovery import create_backup, import_verified_backup, backup_unlock_mode, verify_backup
from .health import check_vault, quarantine_uncommitted


def main():
    parser = argparse.ArgumentParser(prog="blackcube-cli")
    parser.add_argument("--home", type=Path, help="Custom vault location")
    subs = parser.add_subparsers(dest="command", required=True)
    make = subs.add_parser("create")
    make.add_argument("name")
    make.add_argument("--profile", choices=PROFILES + ("none",), default="ML-KEM-768")
    make.add_argument("--create-key-file", type=Path,
                      help="Create separate key file alongside vault at creation")
    subs.add_parser("list")
    portable_enc = subs.add_parser("standalone-encrypt")
    portable_enc.add_argument("source", type=Path)
    portable_enc.add_argument("--key-file", type=Path)
    portable_enc.add_argument("--cipher", choices=("AES-256-GCM", "AES-192-GCM", "AES-128-GCM"), default="AES-256-GCM")
    portable_enc.add_argument("--delete-original", action="store_true")
    portable_enc.add_argument("--yes-delete-original", action="store_true")
    portable_dec = subs.add_parser("standalone-restore")
    portable_dec.add_argument("archive", type=Path)
    portable_dec.add_argument("--to", type=Path, required=True)
    portable_dec.add_argument("--key-file", type=Path)
    portable_key = subs.add_parser("standalone-key-create")
    portable_key.add_argument("path", type=Path)
    backup_import = subs.add_parser("backup-import")
    backup_import.add_argument("path", type=Path)
    backup_import.add_argument("--key-file", type=Path, help="Required key file for a keyfile-only or dual-factor backup")
    for command in ("entries", "encrypt", "hash", "restore", "verify", "change-passphrase", "keyfile-create", "backup", "backup-verify", "health", "keyfile-disable", "keyfile-replace", "access-dual", "access-keyfile", "access-passphrase", "recover-staging") :
        sub = subs.add_parser(command)
        sub.add_argument("vault_id", help="Full or unique initial vault ID")
        sub.add_argument("--key-file", type=Path,
                         help="Unlock using a separate 32-byte recovery key file instead of passphrase")
        if command in ("encrypt", "hash"):
            sub.add_argument("path", type=Path)
        if command == "encrypt":
            sub.add_argument("--hybrid", action="store_true")
            sub.add_argument("--cipher", choices=("AES-256-GCM", "AES-192-GCM", "AES-128-GCM", "ChaCha20-Poly1305"), default="AES-256-GCM")
            sub.add_argument("--delete-originals", action="store_true",
                             help="Remove sources after verified encryption (NOT secure erase)")
            sub.add_argument("--yes-delete-originals", action="store_true",
                             help="Required confirmation flag for deleting originals")
        if command in ("backup", "backup-verify"):
            sub.add_argument("path", type=Path)
        if command in ("keyfile-create", "keyfile-replace", "access-dual", "access-keyfile") :
            sub.add_argument("path", type=Path, help="New external .bckey file path")
        if command in ("restore", "verify"):
            sub.add_argument("entry_id")
        if command == "restore":
            sub.add_argument("--to", type=Path, required=True)
        if command == "verify":
            sub.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.command in ("standalone-encrypt", "standalone-restore", "standalone-key-create", "backup-import"):
            if args.command == "standalone-key-create":
                print("Created key file:", generate_portable_keyfile(args.path))
                return
            if args.command == "backup-import":
                mode = backup_unlock_mode(args.path)
                if mode in ("both", "keyfile") and not args.key_file:
                    raise VaultError("Backup requires --key-file")
                if mode in ("either", "passphrase") and not args.key_file or mode == "both":
                    pwd = getpass.getpass("Backup vault passphrase: ")
                else:
                    pwd = None
                print("Authenticated and restored encrypted vault:",
                      import_verified_backup(args.path, args.home or default_home(),
                                             password=pwd, key_file=args.key_file))
                return
            credential = {"key_file": args.key_file} if args.key_file else {
                "passphrase": getpass.getpass("Standalone passphrase (12+ chars): ")}
            if args.command == "standalone-encrypt" and not args.key_file:
                if credential["passphrase"] != getpass.getpass("Confirm standalone passphrase: "):
                    raise VaultError("Standalone passphrases did not match")
            if args.command == "standalone-encrypt":
                if args.delete_original and not args.yes_delete_original:
                    raise VaultError("Confirm deletion with --yes-delete-original")
                print("Encrypted to:", encrypt_standalone(args.source, **credential,
                      cipher=args.cipher, remove_original=args.delete_original))
            else:
                print("Restored to:", decrypt_standalone(args.archive, args.to, **credential))
            return
        if args.command == "list":
            for d in list_vault_dirs(args.home):
                print(d.name, "(locked)")
            return
        if args.command == "create":
            first = getpass.getpass("New vault passphrase (12+ characters): ")
            second = getpass.getpass("Confirm passphrase: ")
            if first != second:
                raise VaultError("Passphrases do not match")
            profile = None if args.profile == "none" else args.profile
            session = create_vault(args.name, first, profile, args.home)
            if args.create_key_file:
                session.add_keyfile(first, args.create_key_file)
                print("Created separate key file at:", args.create_key_file)
            print("Created", session.name, session.vault_id)
            return
        dirs = [d for d in list_vault_dirs(args.home) if d.name.startswith(args.vault_id)]
        if len(dirs) != 1:
            raise VaultError("No unique matching vault ID")
        mode = _read_config(dirs[0]).get("unlock_mode", "either")
        if mode in ("both", "keyfile") and not args.key_file:
            raise VaultError("This vault requires --key-file")
        if mode in ("both", "passphrase") or (mode == "either" and not args.key_file):
            pwd = getpass.getpass("Vault passphrase: ")
        else:
            pwd = None
        session = open_vault(dirs[0], password=pwd, key_file=args.key_file)
        if args.command == "entries":
            for e in session.entries:
                print(e["id"], e["type"], e["path"], e["mode"])
        elif args.command in ("encrypt", "hash"):
            mode = "Hybrid " + str(session.profile) if args.command == "encrypt" and args.hybrid else (args.cipher if args.command == "encrypt" else "AES-256-GCM")
            removing = args.command == "encrypt" and args.delete_originals
            if removing and not args.yes_delete_originals:
                raise VaultError("Deleting originals requires --yes-delete-originals. This is NOT secure erasure.")
            count, warnings = session.import_path(args.path, mode,
                            hash_only=args.command == "hash", remove_original=removing)
            print(f"Imported {count} entries")
            for warning in warnings:
                print("Warning:", warning)
        elif args.command == "restore":
            print("Restored:", session.restore(args.entry_id, args.to))
        elif args.command == "verify":
            print("MATCH" if session.verify_hash(args.entry_id, args.path) else "MISMATCH")
        elif args.command == "backup":
            print("Backup created:", create_backup(session, args.path))
        elif args.command == "backup-verify":
            print("Backup verified:", verify_backup(session, args.path)['vault_id'])
        elif args.command == "health":
            report = check_vault(session)
            print(report)
            if not report['healthy']:
                raise VaultError('Vault has integrity warnings')
        elif args.command == "recover-staging":
            print("CAUTION: run only with other BlackCube instances closed")
            print(quarantine_uncommitted(session))
        elif args.command == "keyfile-disable":
            session.disable_keyfile(getpass.getpass("Master passphrase: "))
            print("Key-file access disabled for current vault state")
        elif args.command == "keyfile-replace":
            print("Key replaced:", session.replace_keyfile(
                getpass.getpass("Master passphrase: "), args.path))
        elif args.command == "keyfile-create":
            session.add_keyfile(getpass.getpass("Current master passphrase: "), args.path)
            print("Key file saved at:", args.path)
        elif args.command in ("access-dual", "access-keyfile"):
            # Changing authentication policy requires the current passphrase.
            current = getpass.getpass("Reenter current passphrase: ")
            if args.command == "access-dual":
                path = session.require_two_factors(current, args.path)
                print("Both a passphrase and this generated key file are now mandatory:", path)
            else:
                path = session.require_keyfile_only(current, args.path)
                print("This generated key file is now the ONLY live-vault credential:", path)
        elif args.command == "access-passphrase":
            new = getpass.getpass("New passphrase: ")
            if new != getpass.getpass("Repeat new passphrase: "):
                raise VaultError("Passphrases do not match")
            session.require_passphrase_only(new, current_passphrase=pwd, current_key_file=args.key_file)
            print("Vault now requires only the new passphrase")
        elif args.command == "change-passphrase":
            current = getpass.getpass("Confirm old passphrase: ")
            new = getpass.getpass("New passphrase: ")
            confirmation = getpass.getpass("Confirm new passphrase: ")
            if new != confirmation:
                raise VaultError("Passphrases do not match")
            session.change_passphrase(current, new, key_file=args.key_file)
            print("Passphrase updated")
    except (VaultError, OSError, KeyError, ValueError) as exc:
        parser.exit(1, f"BlackCube: {exc}\n")

if __name__ == "__main__":
    main()
