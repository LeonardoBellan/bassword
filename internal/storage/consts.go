package storage

const (
	canaryText = "VERIFICATION_OK"
	canaryID   = 1
)

const (
	createUsersTableSQL = `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            email TEXT NOT NULL UNIQUE,
            Server_Hash BLOB NOT NULL,
            Server_Salt BLOB NOT NULL
        );
    `

	createVaultTableSQL = `CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY, 
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL UNIQUE,
            encrypted_data BLOB,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `

	// Authorization credentials
	verifyAuthDataQuery = `SELECT 1 FROM users WHERE id = ?`

	selectAuthDataQuery = `SELECT Server_Hash, Server_Salt FROM users WHERE id = ?`

	upsertAuthDataQuery = `
        INSERT INTO users(id, Server_Hash, Server_Salt)
        VALUES (?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            Server_Hash = excluded.Server_Hash,
            Server_Salt = excluded.Server_Salt`

	// Credentials
	upsertPasswordQuery = `
        INSERT INTO vault (service_name, username, encrypted_data)
        VALUES (?,?,?)
        ON CONFLICT(service) DO UPDATE SET
            username = excluded.username,
            encrpypted_data = excluded.encrypted_data,
            created_at = CURRENT_TIMESTAMP`

	selectCredentialsByIdQuery = `SELECT id, service_name, username, encrypted_data, created_at
		FROM vault
		WHERE service_name = ?;`
	selectCredentialsByServiceQuery = `SELECT id, service_name, username, encrypted_data, created_at
		FROM vault
		WHERE service_name = ?;`
)
