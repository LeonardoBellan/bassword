package db

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var ErrWrongPassword = errors.New("The master password is not correct")

func OpenDB(ctx context.Context, dbPath string) error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	if err = db.PingContext(ctx); err != nil { return err }
	
	//Ensure DB is initialied correctly, if not initializes it
	if err := setupDB(ctx); err != nil {
		return err
	}

	return nil
}

func CloseDB() error {
	if db == nil {
		return nil
	}
	return db.Close()
}

// Checks if the masterPassword is correct
// Returns ErrWrongPassword if the password is not correct
func verifyMasterPassword(ctx context.Context, masterPassword []byte) ([]byte, error) {
	// Get canary
	var salt []byte
	var canaryCiphertext []byte
	query := selectKdfAndCanaryQuery
	err := db.QueryRowContext(ctx, query, canaryID).Scan(&salt, &canaryCiphertext)
	if err != nil { return nil,err }
	canaryPlaintext,err := crypto.Decrypt(canaryCiphertext,masterPassword,salt)
	if err != nil { return nil,err }

	// Verify canary
	match := subtle.ConstantTimeCompare(canaryPlaintext, []byte(canaryText))
    if match != 1 { return nil, ErrWrongPassword }

	return salt,nil
}

// Adds a new password to the DB, if it already exists for a service updates it with the new values
func AddPassword(ctx context.Context, masterPassword []byte, password []byte, entry *models.CredentialEntry) error {
	//Verify if master password is correct
	salt,err := verifyMasterPassword(ctx,masterPassword)
	defer crypto.Wipe(masterPassword)
	if err != nil { return err }

	entry.EncryptedData, err = crypto.Encrypt(password, masterPassword, salt)
	if err != nil { return err }
	
	query :=
		`INSERT INTO vault (service_name, username, encrypted_data)
		VALUES (?, ?, ?)
		ON CONFLICT(service_name) DO UPDATE SET
			username = excluded.username,
			encrypted_data = excluded.encrypted_data,
			created_at = CURRENT_TIMESTAMP;` // Memorize update time

	_, err = db.ExecContext(ctx,query, entry.ServiceName, entry.Username, entry.EncryptedData)
	return err
}

// Returns the credential entry of the service
func GetCredentialsByService(ctx context.Context, masterPassword []byte, serviceName string) ([]byte,error){
	//Verify if master password is correct
	salt,err := verifyMasterPassword(ctx,masterPassword)
	defer crypto.Wipe(masterPassword)
	if err != nil { return nil,err }
	
	//Get entry of a service
	var entry models.CredentialEntry
	query :=
		`SELECT id, service_name, username, encrypted_data, created_at
		FROM vault
		WHERE service_name = ?;`
	if err := db.QueryRowContext(ctx,query, serviceName).Scan(
		&entry.ID,
		&entry.ServiceName,
		&entry.Username,
		&entry.EncryptedData,
		&entry.CreatedAt,
	); err != nil {
        return nil, err
    }

	//Decrypt password
	password,err := crypto.Decrypt(entry.EncryptedData, masterPassword, salt)
	if err != nil { return nil,err }

	return password,nil
}