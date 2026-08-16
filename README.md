# bassword

Lightweight CLI password manager built in Go.
This is an educational project exploring golang development, client-server architecture and relative security measures.

## Disclaimer

**Warning:** This is a learning project and has not been audited by security professionals. Do not use it for sensitive, real-world credentials. Use audited solutions like Bitwarden, 1Password, or KeePass for production.

## Features

- **Client-Server model** - Decoupled client and server backend.
- **Cobra CLI** - Simple and intuitive terminal interface with memory wiping for the credentials.
- **Zero-Knowledge Architecture** - Encryption and decryption are performed strictly on the client side; the server never receives plain text data or the master password. - **Key Derivation and Separation** - Cryptographic keys and AuthHash are derived from the user's master password using argon2id. - **Client-Side Encryption** - Credentials are secured locally using AES-GCM symmetric encryption before transmission.
- **Authentication** - Performed by sending an authentication hash, which is re-hashed on the server-side to prevent database leakage.
- **Blind indexing** - Supports querying without exposing the user's used services.
- **Cloud-Ready Architecture** - Decoupled business logic and storage layer for fast db migration.

## Installation & Quick Start

### Prerequisites

- Go 1.26 or higher
  _Ensure your Go binary path (e.g., `~/go/bin`) is in your system's `PATH`._

### 1. Installation

Clone the repository and install the binaries of client and server.

```bash
git clone https://github.com/yourusername/bassword.git
cd bassword
go install ./...
```

### 2. Running the server

Start the backend server, it will create a folder '.bassword' in your home directory with a sqlite db 'passwords.db' inside.

```bash
bassword-server
```

### 3. Register a user in the CLI client

In a new terminal window, register your client and start managing credentials:

```bash
bassword register user@example.com
```

---

## Usage of the CLI client

### Add a Password

Store a new credential. You will be prompted to enter the password securely. The password will be copied in your clipboard.

```bash
bassword add [service] [username]
```

**Flags:**

- `-r, --random`: Automatically generate a random password.
- `-l, --length <int>`: Specify generated password length (default: 16).

### Retrieve a Password

Get a stored password (requires your Master Password). The password will be copied in your clipboard.

```bash
bassword get [service]
```

---

## License

MIT License. See `LICENSE` for details.
