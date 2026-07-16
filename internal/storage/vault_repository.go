package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type VaultRepository struct {
	conn *sql.DB
}

// Dependency injection
func NewVaultRepository(conn *sql.DB) *VaultRepository {
    return &VaultRepository{conn: conn}
}

// Adds a new password to the DB; if it already exists for a service, it updates it with the new values.
// Populates the given credential with ID and createdAt fields
func (r *VaultRepository) AddCredential(ctx context.Context, credentials *models.Credentials) error {
	err := r.conn.QueryRowContext(ctx, upsertCredentialsQuery, credentials.UserID, credentials.ServiceName, credentials.EncryptedData).Scan(&credentials.ID,&credentials.CreatedAt)
	return err
}

// Returns the credential entry of the service of a user
func (r *VaultRepository) GetCredentialsByUserAndService(ctx context.Context, userID int, serviceName string) (models.Credentials, error) {
	// Get entry of a service
	var credentials models.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByUserAndServiceQuery, userID, serviceName).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceName,
		&credentials.EncryptedData,
		&credentials.CreatedAt,
	); err != nil {
		return models.Credentials{}, err
	}

	return credentials, nil
}

// Returns the credential entry corresponding to the ID
func (r *VaultRepository) GetCredentials(ctx context.Context, ID int) (models.Credentials, error) {
	// Get entry of a service
	var credentials models.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByIdQuery, ID).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceName,
		&credentials.EncryptedData,
		&credentials.CreatedAt,
	); err != nil {
		return models.Credentials{}, err
	}

	return credentials, nil
}

// Returns the services associated to a user
func (r *VaultRepository) GetServicesByUserID(ctx context.Context, ID int) ([]string, error) {
	//TODO

	return nil, nil
}