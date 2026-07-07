package db

const (
	canaryText = "VERIFICATION_OK"
	canaryID   = 1
)

const (
	createVaultTableSQL = `CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY, 
            service_name TEXT NOT NULL UNIQUE,
            username TEXT,
            encrypted_data BLOB,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `

	createConfigTableSQL = `CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY CHECK (id = 1), 
            kdf_salt BLOB NOT NULL,
            canary_ciphertext BLOB NOT NULL
        );
    `

	selectCanaryQuery = `SELECT 1 FROM app_config WHERE id = ?`

	upsertCanaryQuery = `
        INSERT INTO app_config(id,kdf_salt,canary_ciphertext)
        VALUES (?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            kdf_salt = excluded.kdf_salt,
            canary_ciphertext = excluded.canary_ciphertext`

	selectKdfAndCanaryQuery = `SELECT kdf_salt,canary_ciphertext FROM app_config WHERE id = ?`
)
