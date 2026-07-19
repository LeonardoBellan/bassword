package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/domain"
)

type SQLiteVaultRepository struct {
	conn *sql.DB
}

func NewSQLiteVaultRepository(conn *sql.DB) *SQLiteVaultRepository {
    return &SQLiteVaultRepository{conn: conn}
}

// Adds a new password to the DB; if it already exists for a service, it updates it with the new values.
// Populates the given credential with ID and createdAt fields
func (r *SQLiteVaultRepository) Save(ctx context.Context, credentials *domain.Credentials) error {
	err := r.conn.QueryRowContext(ctx, upsertCredentialsQuery, credentials.UserID, credentials.ServiceName, credentials.EncryptedData).Scan(&credentials.ID,&credentials.CreatedAt)
	return err
}


// Returns the credential entry corresponding to the ID
func (r *SQLiteVaultRepository) GetByIdAndUser(ctx context.Context, id int, userID int) (*domain.Credentials, error) {
	// Get entry of a service
	var credentials domain.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByIdAndUserQuery, id, userID).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceName,
		&credentials.EncryptedData,
		&credentials.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &credentials, nil
}

// Returns the credential entry of the service of a user
func (r *SQLiteVaultRepository) GetByServiceAndUser(ctx context.Context, serviceName string, userID int) (*domain.Credentials, error) {
	// Get entry of a service
	var credentials domain.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByServiceAndUserQuery, serviceName, userID).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceName,
		&credentials.EncryptedData,
		&credentials.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &credentials, nil
}

/* TODOs

// Returns the services associated to a user
func (r *SQLiteSQLiteVaultRepository) ListServicesByUser(ctx context.Context, userID int) ([]string, error) {
	//TODO

	return nil, nil
}
*/