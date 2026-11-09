import os
import sys
import json
import argparse
import getpass
import re
import logging
import stat
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

VAULT_FILE = "vault.json"
LOG_FILE = "pm_secure.log"

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
KEY_LEN_BYTES = 32

MAX_INPUT_LEN = 255
VALID_PATTERN = re.compile(r'^[A-Za-z0-9_.@:-]+$')

logger = logging.getLogger("SecurePasswordManager")
logger.setLevel(logging.INFO)
log_handler = logging.FileHandler(LOG_FILE)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        return json.dumps(log_obj)

log_handler.setFormatter(JSONFormatter())
logger.addHandler(log_handler)

def wipe_bytearray(value):
    if isinstance(value, bytearray):
        for index in range(len(value)):
            value[index] = 0


def read_secret(prompt: str, max_length: int = 1024) -> bytearray:
    entered = getpass.getpass(prompt)
    try:
        encoded = bytearray(entered.encode("utf-8"))
    finally:
        del entered

    if not encoded or len(encoded) > max_length:
        wipe_bytearray(encoded)
        print("Error: Invalid secret length.", file=sys.stderr)
        sys.exit(1)
    return encoded


def sanitize_input(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_INPUT_LEN:
        logger.error("Input validation failure.")
        print("Error: Invalid input format.", file=sys.stderr)
        sys.exit(1)
    if not VALID_PATTERN.fullmatch(value):
        logger.error("Input validation failure.")
        print("Error: Invalid input format.", file=sys.stderr)
        sys.exit(1)
    return value


def validate_vault_structure(data: dict):
    try:
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError
        if not isinstance(data.get("owner_uid"), int):
            raise ValueError

        kdf = data["kdf"]
        encryption = data["encryption"]
        secrets = data["secrets"]

        if not isinstance(kdf, dict) or kdf.get("algorithm") != "Argon2id":
            raise ValueError
        salt = bytes.fromhex(kdf["salt"])
        if len(salt) != 16:
            raise ValueError

        if not isinstance(encryption, dict) or encryption.get("algorithm") != "AES-256-GCM":
            raise ValueError
        verifier_nonce = bytes.fromhex(encryption["verifier_nonce"])
        verifier_ciphertext = bytes.fromhex(encryption["verifier_ciphertext"])
        if len(verifier_nonce) != 12 or len(verifier_ciphertext) < 16:
            raise ValueError

        if not isinstance(secrets, dict):
            raise ValueError
        for site, record in secrets.items():
            if not isinstance(site, str) or not VALID_PATTERN.fullmatch(site):
                raise ValueError
            if not isinstance(record, dict):
                raise ValueError
            nonce = bytes.fromhex(record["nonce"])
            ciphertext = bytes.fromhex(record["ciphertext"])
            if len(nonce) != 12 or len(ciphertext) < 16:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        logger.error("Vault structure validation failed.")
        print("Error: Critical integrity failure.", file=sys.stderr)
        sys.exit(1)


def enforce_access_control(filepath: str, action: str):
    if not os.path.exists(filepath):
        return

    try:
        stat_info = os.stat(filepath, follow_symlinks=False)
        current_uid = os.getuid() if hasattr(os, "getuid") else None

        if current_uid is not None and hasattr(stat_info, "st_uid"):
            if stat_info.st_uid != current_uid:
                logger.error("Access control denied for vault operation.")
                print("Error: Access denied.", file=sys.stderr)
                sys.exit(1)

        if os.name == "posix" and stat.S_IMODE(stat_info.st_mode) & 0o077:
            logger.error("Vault permissions are too permissive.")
            print("Error: Vault file permissions are insecure.", file=sys.stderr)
            sys.exit(1)

        if not stat.S_ISREG(stat_info.st_mode):
            logger.error("Vault path is not a regular file.")
            print("Error: Access denied.", file=sys.stderr)
            sys.exit(1)
    except OSError:
        logger.error("Access metadata verification failed.")
        print("Error: Access verification failure.", file=sys.stderr)
        sys.exit(1)


def derive_master_key(password: str, salt: bytes) -> bytes:
    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN_BYTES,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
            ad=None,
            secret=None
        )
        return kdf.derive(bytes(password) if isinstance(password, bytearray) else password.encode('utf-8'))
    except Exception as e:
        logger.critical(f"Cryptographic derivation failure: {str(e)}")
        print("Error: An unexpected internal error occurred.", file=sys.stderr)
        sys.exit(1)

def load_vault_file() -> dict:
    enforce_access_control(VAULT_FILE, "read")
    if not os.path.exists(VAULT_FILE):
        logger.warning("Vault lookup attempted before initialization.")
        print("Error: Operational path missing. Run 'init' first.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as vault_file:
            data = json.load(vault_file)
        validate_vault_structure(data)

        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and data["owner_uid"] != current_uid:
            logger.error("Vault metadata owner does not match current user.")
            print("Error: Access denied.", file=sys.stderr)
            sys.exit(1)
        return data
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        logger.error("Vault could not be read or parsed.")
        print("Error: Critical integrity failure.", file=sys.stderr)
        sys.exit(1)


def write_vault_file(data: dict):
    enforce_access_control(VAULT_FILE, "write")
    file_descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_descriptor = os.open(VAULT_FILE, flags, 0o600)

        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, 0o600)

        with os.fdopen(file_descriptor, "w", encoding="utf-8") as vault_file:
            file_descriptor = None
            json.dump(data, vault_file, indent=4)
            vault_file.flush()
            os.fsync(vault_file.fileno())
    except Exception:
        if file_descriptor is not None:
            os.close(file_descriptor)
        logger.error("Vault storage operation failed.")
        print("Error: Storage layer unreachable.", file=sys.stderr)
        sys.exit(1)


def cmd_init():
    if os.path.exists(VAULT_FILE):
        enforce_access_control(VAULT_FILE, "overwrite")
        confirm = input("Vault already exists. Overwrite? (y/N): ").strip().lower()
        if confirm != "y":
            logger.info("Vault initialization canceled.")
            sys.exit(0)

    print("--- Initialize Password Vault ---")
    mp1 = read_secret("Enter Master Password: ")
    mp2 = read_secret("Confirm Master Password: ")

    try:
        if mp1 != mp2:
            logger.warning("Vault initialization password mismatch.")
            print("Error: Credentials do not match.", file=sys.stderr)
            sys.exit(1)

        salt = os.urandom(16)
        master_key = derive_master_key(mp1, salt)

        v_plaintext = b"vault_authenticated"
        v_nonce = os.urandom(12)
        aesgcm = AESGCM(master_key)
        v_ciphertext = aesgcm.encrypt(v_nonce, v_plaintext, None)

        current_uid = os.getuid() if hasattr(os, "getuid") else 0
        vault_structure = {
            "version": 1,
            "owner_uid": current_uid,
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
        logger.info("New vault initialized successfully.")
        print(f"Success: Vault initialized at '{VAULT_FILE}'.")
    finally:
        wipe_bytearray(mp1)
        wipe_bytearray(mp2)


def verify_and_get_key(vault: dict) -> bytes:
    mp = read_secret("Enter Master Password: ")
    try:
        salt = bytes.fromhex(vault["kdf"]["salt"])
        master_key = derive_master_key(mp, salt)

        v_nonce = bytes.fromhex(vault["encryption"]["verifier_nonce"])
        v_cipher = bytes.fromhex(vault["encryption"]["verifier_ciphertext"])

        aesgcm = AESGCM(master_key)
        decrypted = aesgcm.decrypt(v_nonce, v_cipher, None)
        if decrypted == b"vault_authenticated":
            return master_key
    except (InvalidTag, ValueError, KeyError, TypeError):
        logger.warning("Authentication failed.")
    finally:
        wipe_bytearray(mp)

    print("Error: Authentication failed.", file=sys.stderr)
    sys.exit(1)


def cmd_add(args):
    site = sanitize_input(args.site)
    username = sanitize_input(args.username)
    
    vault = load_vault_file()
    master_key = verify_and_get_key(vault)

    secret_password = read_secret(f"Enter secret password for {username}@{site}: ")

    try:
        secret_payload = {
            "username": username,
            "password": secret_password.decode("utf-8")
        }

        nonce = os.urandom(12)
        aesgcm = AESGCM(master_key)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(secret_payload).encode('utf-8'), None)

        vault["secrets"][site] = {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

        write_vault_file(vault)
        logger.info(f"Credential added succesfully.")
        print(f"Success: Credential added for '{site}'.")
    finally:
        wipe_bytearray(secret_password)

def cmd_get(args):
    site = sanitize_input(args.site)
    vault = load_vault_file()

    if site not in vault["secrets"]:
        logger.warning("Credential lookup did not match a stored service.")
        print("Error: Record not found.", file=sys.stderr)
        sys.exit(1)

    master_key = verify_and_get_key(vault)
    target = vault["secrets"][site]

    try:
        s_nonce = bytes.fromhex(target["nonce"])
        s_cipher = bytes.fromhex(target["ciphertext"])
        aesgcm = AESGCM(master_key)
        decrypted_bytes = aesgcm.decrypt(s_nonce, s_cipher, None)
        record = json.loads(decrypted_bytes.decode("utf-8"))

        if not isinstance(record, dict):
            raise ValueError

        username = sanitize_input(record.get("username"))
        password = record.get("password")
        if not isinstance(password, str):
            raise ValueError

        print("\\n--- Credentials ---")
        print(f"Site:     {site}")
        print(f"Username: {username}")
        print(f"Password: {password}")
    except (InvalidTag, ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        logger.error("Credential decryption or record validation failed.")
        print("Error: Vault decryption failed.", file=sys.stderr)
        sys.exit(1)


def cmd_list():
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
