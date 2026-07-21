package storage

const (
	createUsersTableSQL = `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, 
            email TEXT NOT NULL UNIQUE,
            server_hash BLOB NOT NULL,
            server_salt BLOB NOT NULL
        );`

	createVaultTableSQL = `CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY, 
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, service_name)
        );`

	// Users
	upsertUserQuery = `
        INSERT INTO users(email, server_hash, server_salt)
        VALUES (?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            email = excluded.email,
            server_hash = excluded.server_hash,
            server_salt = excluded.server_salt
        RETURNING id`

	selectUserByIdQuery = `
        SELECT id, email, server_hash, server_salt
        FROM users WHERE id = ?`

	selectUserByEmailQuery = `
        SELECT id, email, server_hash, server_salt
        FROM users WHERE email = ?`

	// Credentials
	upsertCredentialsQuery = `
        INSERT INTO vault (user_id, service_name, encrypted_data)
        VALUES (?,?,?)
        ON CONFLICT(user_id, service_name) DO UPDATE SET
            encrypted_data = excluded.encrypted_data,
            created_at = CURRENT_TIMESTAMP
        RETURNING id, created_at`

	selectCredentialsByIdAndUserQuery = `
        SELECT *
		FROM vault
		WHERE id = ? AND user_id = ?;`
	selectCredentialsByServiceAndUserQuery = `
        SELECT *
		FROM vault
		WHERE service_name = ? AND user_id = ?;`
)
