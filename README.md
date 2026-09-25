# Secure CLI Password Manager (Python)

## Project scope
This project is a single-user offline password vault. It is designed to securely derive encryption keys from a master password, encrypt credentials locally and manage secrets via a terminal environment. 

Out of scope: cloud synchronization, multi-user accounts and browser extension integration.

## Planned command-Line commands
The application will be controlled using the following terminal interface:
* python pm.py init - prompts for and registers a new master password, initializing the secure local vault file.
* python pm.py add --site <name> --username <user> - prompts for a secret password securely, encrypts it and adds it to the vault.
* python pm.py get --site <name> - prompts for the master password, decrypts the record and displays the matching credentials.
* python pm.py list - decrypts and lists the names of all registered services currently stored in the vault without revealing passwords.

## How to build and run
1. Clone this repository
2. Install the required cryptographic dependencies: pip install -r requirements.txt
3. Execute the CLI entry point helper: python pm.py --help
