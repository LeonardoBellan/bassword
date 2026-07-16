package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type Repository struct {
	conn *sql.DB
}

// Dependency injection
func NewRepository(conn *sql.DB) *Repository {
    return &Repository{conn: conn}
}

func (r *Repository) Close() error {
	if r.conn == nil { return nil }
	return r.conn.Close()
}

//TODO: Remove and verify authHash
// Checks if the masterPassword is correct
// Returns ErrWrongPassword if the password is not correct
/*func (r *Repository) verifyMasterPassword(ctx context.Context, masterPassword []byte) ([]byte, error) {
	// Get canary
	var salt []byte
	var canaryCiphertext []byte
	query := selectKdfAndCanaryQuery
	err := r.conn.QueryRowContext(ctx, query, canaryID).Scan(&salt, &canaryCiphertext)
	if err != nil { return nil,err }
	canaryPlaintext,err := crypto.Decrypt(canaryCiphertext,masterPassword,salt)
	if err != nil { return nil,err }

	// Verify canary
	match := subtle.ConstantTimeCompare(canaryPlaintext, []byte(canaryText))
    if match != 1 { return nil, ErrWrongPassword }

	return salt,nil
}*/



// Adds a new password to the DB; if it already exists for a service, it updates it with the new values.
func (r *Repository) AddCredential(ctx context.Context, entry *models.CreateCredentialInput) error {
	_, err := r.conn.ExecContext(ctx, upsertPasswordQuery, entry.ServiceName, entry.Username, entry.EncryptedData)
	return err
}

// Returns the credential entry of the service
func (r *Repository) GetCredentialsByService(ctx context.Context, serviceName string) (models.CredentialEntry, error) {
	// Get entry of a service
	var entry models.CredentialEntry
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByServiceQuery, serviceName).Scan(
		&entry.ID,
		&entry.ServiceName,
		&entry.Username,
		&entry.EncryptedData,
		&entry.CreatedAt,
	); err != nil {
		return models.CredentialEntry{}, err
	}

	return entry, nil
}

// Returns the credential entry corresponding to the ID
func (r *Repository) GetCredentialsByID(ctx context.Context, ID int) (models.CredentialEntry, error) {
	// Get entry of a service
	var entry models.CredentialEntry
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByIdQuery, ID).Scan(
		&entry.ID,
		&entry.ServiceName,
		&entry.Username,
		&entry.EncryptedData,
		&entry.CreatedAt,
	); err != nil {
		return models.CredentialEntry{}, err
	}

	return entry, nil
}