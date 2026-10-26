import os
import sys
import json
import argparse
import getpass
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

VAULT_FILE = "vault.json"

# Cryptographic configuration established in Checkpoint 1
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
KEY_LEN_BYTES = 32

def derive_master_key(password: str, salt: bytes) -> bytes:
    """Derives a secure key using Argon2id configuration."""
    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN_BYTES,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
        ad=None,
        secret=None
    )
    return kdf.derive(password.encode('utf-8'))

def load_vault_file() -> dict:
    """Basic file loading layer."""
    if not os.path.exists(VAULT_FILE):
        print(f"Error: Vault file '{VAULT_FILE}' not found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def write_vault_file(data: dict):
    """Basic file writing layer."""
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4)

def cmd_init():
    """Initializes a new vault with an Argon2id key and a verifier block."""
    if os.path.exists(VAULT_FILE):
        confirm = input("Vault already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Initialization cancelled.")
            sys.exit(0)

    print("--- Initialize Password Vault ---")
    mp1 = getpass.getpass("Enter Master Password: ")
    mp2 = getpass.getpass("Confirm Master Password: ")

    if mp1 != mp2:
        print("Error: Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    salt = os.urandom(16)
    master_key = derive_master_key(mp1, salt)

    # Setup a verification block to allow implicit authentication via AES-GCM tags
    v_plaintext = b"vault_authenticated"
    v_nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    v_ciphertext = aesgcm.encrypt(v_nonce, v_plaintext, None)

    vault_structure = {
        "version": 1,
        "kdf": {
            "algorithm": "Argon2id",
            "salt": salt.hex(),
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "verifier_nonce": v_nonce.hex(),
            "verifier_ciphertext": v_ciphertext.hex()
        },
        "secrets": {}
    }

    write_vault_file(vault_structure)
    print(f"Success: Vault initialized at '{VAULT_FILE}'.")

def verify_and_get_key(vault: dict) -> bytes:
    """Prompts for master password and verifies it against the GCM verifier tag."""
    mp = getpass.getpass("Enter Master Password: ")
    salt = bytes.fromhex(vault["kdf"]["salt"])
    master_key = derive_master_key(mp, salt)

    v_nonce = bytes.fromhex(vault["encryption"]["verifier_nonce"])
    v_cipher = bytes.fromhex(vault["encryption"]["verifier_ciphertext"])

    try:
        aesgcm = AESGCM(master_key)
        decrypted = aesgcm.decrypt(v_nonce, v_cipher, None)
        if decrypted == b"vault_authenticated":
            return master_key
    except InvalidTag:
        pass

    print("Error: Invalid Master Password.", file=sys.stderr)
    sys.exit(1)

def cmd_add(args):
    """Encrypts credentials and appends them to the storage layer."""
    vault = load_vault_file()
    master_key = verify_and_get_key(vault)

    # Secure entry: getpass masks input characters on screen
    secret_password = getpass.getpass(f"Enter secret password for {args.username}@{args.site}: ")

    secret_payload = {
        "username": args.username,
        "password": secret_password
    }

    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(secret_payload).encode('utf-8'), None)

    vault["secrets"][args.site] = {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    write_vault_file(vault)
    print(f"Success: Credential added for '{args.site}'.")

def cmd_get(args):
    """Decrypts and reveals matching credentials for a targeted site."""
    vault = load_vault_file()

    if args.site not in vault["secrets"]:
        print(f"Error: Record for '{args.site}' not found.", file=sys.stderr)
        sys.exit(1)

    master_key = verify_and_get_key(vault)
    target = vault["secrets"][args.site]

    s_nonce = bytes.fromhex(target["nonce"])
    s_cipher = bytes.fromhex(target["ciphertext"])

    try:
        aesgcm = AESGCM(master_key)
        decrypted_bytes = aesgcm.decrypt(s_nonce, s_cipher, None)
        record = json.loads(decrypted_bytes.decode('utf-8'))

        print("\n--- Credentials ---")
        print(f"Site:     {args.site}")
        print(f"Username: {record['username']}")
        print(f"Password: {record['password']}")
    except InvalidTag:
        print("Error: Failed to decrypt payload; integrity tag verification failed.", file=sys.stderr)
        sys.exit(1)

def cmd_list():
    """Lists the service metadata keys stored in the vault index."""
    vault = load_vault_file()
    verify_and_get_key(vault)

    sites = list(vault["secrets"].keys())
    print("\n--- Stored Services ---")
    if not sites:
        print("[No secrets found]")
    for site in sites:
        print(f" • {site}")

def main():
    parser = argparse.ArgumentParser(description="Secure CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init")

    parser_add = subparsers.add_parser("add")
    parser_add.add_argument("--site", required=True)
    parser_add.add_argument("--username", required=True)

    parser_get = subparsers.add_parser("get")
    parser_get.add_argument("--site", required=True)

    subparsers.add_parser("list")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "add":
        cmd_add(args)
    elif args.command == "get":
        cmd_get(args)
    elif args.command == "list":
        cmd_list()

if __name__ == "__main__":
    main()
