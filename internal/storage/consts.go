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
        );`

	createVaultTableSQL = `CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY, 
            user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            encrypted_data BLOB,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, service_name)
        );`

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
	upsertCredentialsQuery = `
        INSERT INTO vault (user_id, service_name, encrypted_data)
        VALUES (?,?,?)
        ON CONFLICT(user_id, service_name) DO UPDATE SET
            encrypted_data = excluded.encrypted_data,
            created_at = CURRENT_TIMESTAMP
        RETURNING id, created_at`

	selectCredentialsByIdQuery = `
        SELECT *
		FROM vault
		WHERE id = ?;`
	selectCredentialsByUserAndServiceQuery = `
        SELECT *
		FROM vault
		WHERE user_id = ? AND service_name = ?;`
)
