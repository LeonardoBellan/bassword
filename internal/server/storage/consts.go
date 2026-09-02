package storage

const (
	createUsersTableSQL = `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY, 
			email TEXT NOT NULL UNIQUE,
			secret_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`

	createVaultTableSQL = `
		CREATE TABLE IF NOT EXISTS vault (
			id TEXT PRIMARY KEY, 
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			service_index BLOB NOT NULL,
			service_encrypted BLOB NOT NULL,
			data_encrypted BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, service_index)
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
    INSERT INTO vault (id, user_id, service_index, service_encrypted, data_encrypted)
    VALUES (?,?,?,?,?)
    ON CONFLICT(user_id, service_index) DO UPDATE SET
			service_encrypted = excluded.service_encrypted,
			data_encrypted = excluded.data_encrypted,
			created_at = CURRENT_TIMESTAMP
    RETURNING created_at`

	selectCredentialsByIdAndUserQuery = `
    SELECT *
		FROM vault
		WHERE id = ? AND user_id = ?;`

	selectCredentialsByServiceAndUserQuery = `
    SELECT *
		FROM vault
		WHERE service_index = ? AND user_id = ?;`
)
