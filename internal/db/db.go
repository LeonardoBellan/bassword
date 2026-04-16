package db

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"

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
		//TODO: in other functions after calling it check for ErrDBNotInitialized
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


func insertCanary(ctx context.Context, masterPassword []byte) error {
	defer crypto.Wipe(masterPassword)

	canaryText := "VERIFICATION_OK"
	salt := make([]byte, 16)
	rand.Read(salt)
	canaryCiphertext,err := crypto.Encrypt([]byte(canaryText), masterPassword, salt)
	if err != nil { return err }


	fmt.Println("salt " , salt)
	fmt.Println("ciphertext ",canaryCiphertext)

	query := `
		INSERT INTO app_config(id,kdf_salt,canary_ciphertext)
		VALUES (1,?,?)
		ON CONFLICT(id) DO UPDATE SET
			kdf_salt = excluded.kdf_salt,
			canary_ciphertext = excluded.canary_ciphertext`;
	_, err = db.ExecContext(ctx,query,salt,canaryCiphertext)
	if err != nil { return err }
	

	fmt.Println("CANARY INSERITO IN TEORIA")
	return nil
}

// InitializeDB initializes the database with the master password
func InitializeDB(ctx context.Context, masterPassword []byte) error {
	return insertCanary(ctx, masterPassword)
}

// Checks if the masterPassword is correct
// Returns ErrWrongPassword if the password is not correct
func verifyMasterPassword(ctx context.Context, masterPassword []byte) ([]byte, error) {
	expectedCanary := "VERIFICATION_OK"

	// Get canary
	var salt []byte
	var canaryCiphertext []byte
	query := `SELECT kdf_salt,canary_ciphertext FROM app_config WHERE id = 1`
	err := db.QueryRowContext(ctx,query).Scan(&salt,&canaryCiphertext)
	if err != nil { return nil,err }
	canaryPlaintext,err := crypto.Decrypt(canaryCiphertext,masterPassword,salt)
	if err != nil { return nil,err }

	// Verify canary
    match := subtle.ConstantTimeCompare(canaryPlaintext, []byte(expectedCanary))
    if match != 1 { return nil,ErrWrongPassword }

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