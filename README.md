# Secure Password Manager

A secure password manager written in Rust that uses robust cryptographic operations with AES-256-GCM for encryption and Argon2id for master key derivation.

## Features

- **Secure Encryption:** Uses AES-256-GCM for encrypting your vault data.
- **Master Key Derivation:** Derives the master key from a user-supplied password using Argon2id with a randomly generated salt.
- **Data Integrity:** Stores the salt alongside the encrypted data to ensure consistent decryption.
- **Credential Management:** Easily add, retrieve, update, and remove credentials for various services.
- **Command-line Interface:** Interact with your vault through a CLI with commands such as `init`, `add`, `get`, `update`, and `remove`.
- **Debug Logging:** Built-in debug messages help trace vault operations, including salt generation, encryption, and decryption steps.

## Setup and Installation

1. **Clone the Repository:**
   ```bash
   git clone <repository-url>
   cd secure_password_manager
   ```

2. **Build the Project:**
   ```bash
   cargo build
   ```

3. **Run Tests:**
   ```bash
   cargo test
   ```

## Usage

### Initialize the Vault

To create a new vault, use the following command. This will prompt you to enter and confirm your master password. **Choose a strong password, as it is required to decrypt your vault and cannot be recovered if forgotten.**

```bash
cargo run -- init --force
```

### Adding a Credential

To add a new credential (for example, for GitHub), run:

```bash
cargo run -- add --service GitHub --username myusername --generate --symbols
```

This command will:
- Prompt for the master password to load your vault.
- Generate a secure password if the `--generate` flag is provided.
- Encrypt and save the credential in the vault.

### Retrieving a Credential

To retrieve a credential, specify the service and optionally the username (if multiple credentials exist for the service):

```bash
cargo run -- get --service GitHub --username myusername
```

If only one credential exists for a service and no username is provided, that credential will be returned.

### Updating a Credential

To update an existing credential (e.g., change your password or add notes):

```bash
cargo run -- update --service Email --username user@example.com --password newpassword --notes "Updated notes"
```

### Removing a Credential

To remove a credential from your vault:

```bash
cargo run -- remove --service GitHub --username myusername
```

### Changing the Master Password

To change the master password (this operation updates the vault's salt and re-encrypts your data):

```bash
cargo run -- change-master-password --new "new_master_password"
```

## Debugging

The application includes debug log messages that print key operational details (e.g., salt values, JSON sizes, encryption/decryption status). If you experience issues such as decryption failures or authentication errors, review the debug output for insights into where the process may be failing.

## Project Structure

- `src/encryption/crypto.rs`: Handles cryptographic operations, including encryption, decryption, and salt generation.
- `src/credential_manager/vault.rs`: Manages vault operations such as initialization, saving, loading, and credential management.
- `src/utils/`: Contains constants and error definitions used throughout the application.

## Contributing

Contributions are welcome! Please follow standard Rust coding guidelines, write tests for new features, and ensure all tests pass before submitting a pull request.


## Acknowledgments

- The Rust community for providing excellent libraries and tools
- Inspiration from other password managers like KeePass, Bitwarden, and 1Password 
