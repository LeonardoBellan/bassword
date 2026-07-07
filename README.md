# bassword

A lightweight CLI password manager built in Go. This is an educational project exploring CLI development and basic cryptography.

## Features

- **Local Storage:** Passwords are encrypted and stored locally.
- **Security Concepts:** Implements key derivation and symmetric encryption.
- **Cobra CLI:** Intuitive terminal interface.

## Installation and initialization

Make sure you have Go (1.16+) installed, then run:

```bash
git clone https://github.com/yourusername/bassword.git
cd bassword
go install
```

_Ensure your Go binary path (e.g., `~/go/bin`) is in your system's `PATH`._

Then setup the database and create your Master Password

```bash
bassword init
```

_Note: The Master Password is used for encryption and cannot be recovered if lost._

## Database / Initialization

- **DB canary:** The app stores a KDF salt and an encrypted canary value in the `app_config` table (row `id = 1`) to verify the master password.
- **Canary plaintext:** `VERIFICATION_OK`.
- **Developer note:** `internal/db/consts.go` contains SQL statements and constants used by the DB layer (canary value, table creation SQL, queries). The canary row is parametrized using `canaryID` to avoid magic literals.

If you change the canary text or the DB schema, reinitialize the database with `bassword init`.

---

## Usage

### Add a Password

Store a new credential. You will be prompted to enter the password securely. The password will be copied in your clipboard.

```bash
bassword add [service] [username]
```

**Flags:**

- `-g, --generate`: Automatically generate a random password.
- `-l, --length <int>`: Specify generated password length (default: 16).

### Retrieve a Password

Get a stored password (requires your Master Password). The password will be copied in your clipboard.

```bash
bassword get [service]
```

---

## Security Measures

As an educational tool, this project implements standard practices:

1. **Key Derivation:** Master passwords are not stored; they generate a 256-bit encryption using Argon2id.
2. **Encryption:** Data is secured using AES-256-GCM.
3. **Local Database:** No data leaves your machine.
4. **Memory Wipe:** After using the master password and passwords they are removed from memory.
5. **Clipboard timeout:** The clipboard is cleared (If still containing the password) after a certain amount of time.
6.

---

## Disclaimer

**Warning:** This is a learning project and has not been audited by security professionals. Do not use it for sensitive, real-world credentials. Use audited solutions like Bitwarden, 1Password, or KeePass for production.

## License

MIT License. See `LICENSE` for details.
