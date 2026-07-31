package storage

const (
	createUsersTableSQL = `CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, 
            email TEXT NOT NULL UNIQUE,
            secret_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );`

	createVaultTableSQL = `CREATE TABLE IF NOT EXISTS vault (
            id TEXT PRIMARY KEY, 
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, service_name)
        );`

	// Users
	insertUserQuery = `
        INSERT INTO users(id, email, secret_hash)
        VALUES (?, ?, ?)
        RETURNING created_at`

	selectUserByIdQuery = `
        SELECT id, email, secret_hash
        FROM users WHERE id = ?`

	selectUserByEmailQuery = `
        SELECT id, email, secret_hash
        FROM users WHERE email = ?`

	// Credentials
	upsertCredentialsQuery = `
        INSERT INTO vault (id, user_id, service_name, encrypted_data)
        VALUES (?,?,?,?)
        ON CONFLICT(user_id, service_name) DO UPDATE SET
            encrypted_data = excluded.encrypted_data,
            created_at = CURRENT_TIMESTAMP
        RETURNING created_at`

	selectCredentialsByIdAndUserQuery = `
        SELECT *
		FROM vault
		WHERE id = ? AND user_id = ?;`

	selectCredentialsByServiceAndUserQuery = `
        SELECT *
		FROM vault
		WHERE service_name = ? AND user_id = ?;`
)
