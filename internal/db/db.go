package db

import (
	"database/sql"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(path string) error {
	var err error
	DB, err = sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	/* Create table if not exists */
	query :=
		`CREATE TABLE IF NOT EXISTS credentials (
			id INTEGER PRIMARY KEY, 
			service_name TEXT NOT NULL UNIQUE,
			username TEXT,
			encrypted_data BLOB,
			salt BLOB,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`
	_, err = DB.Exec(query)
	if err != nil { return err }

	return nil
}

/* Adds a new password to the DB, if it already exists for a service updates it with the new values */
func AddPassword(entry *models.CredentialEntry) error {
	query :=
		`INSERT INTO credentials (service_name, username, encrypted_data, salt)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(service_name) DO UPDATE SET
			username = excluded.username,
			encrypted_data = excluded.encrypted_data,
			salt = excluded.salt,
			created_at = CURRENT_TIMESTAMP;` // Memorize update time

	_, err := DB.Exec(query, entry.ServiceName, entry.Username, entry.EncryptedData, entry.Salt)
	return err
}

func GetCredentialsByService(serviceName string) (*models.CredentialEntry,error){
	var entry models.CredentialEntry
	
	query :=
		`SELECT id, service_name, username, encrypted_data, salt, created_at
		FROM credentials
		WHERE service_name = ?;`
	err := DB.QueryRow(query, serviceName).Scan(
		&entry.ID,
		&entry.ServiceName,
		&entry.Username,
		&entry.EncryptedData,
		&entry.Salt,
		&entry.CreatedAt,
	)
	if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("nessuna credenziale trovata per: %s", serviceName)
        }
        return nil, err
    }
	return &entry, nil
}