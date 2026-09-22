package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/google/uuid"
)

type PostgresVaultRepository struct {
	conn *sql.DB
}

func NewPostgresVaultRepository(conn *sql.DB) *PostgresVaultRepository {
    return &PostgresVaultRepository{conn: conn}
}

// Adds a new password to the DB; if it already exists for a service, it updates it with the new values.
// Populates the given credential with ID and createdAt fields
func (r *PostgresVaultRepository) Save(ctx context.Context, credentials *domain.Credentials) error {
	upsertCredentialsQuery := `
    INSERT INTO vault (id, user_id, service_index, service_encrypted, data_encrypted)
    VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT(user_id, service_index) DO UPDATE SET
			service_encrypted = excluded.service_encrypted,
			data_encrypted = excluded.data_encrypted,
			created_at = CURRENT_TIMESTAMP
    RETURNING created_at`

	err := r.conn.QueryRowContext(ctx, upsertCredentialsQuery, credentials.ID, credentials.UserID, credentials.ServiceIndex, credentials.ServiceEncrypted, credentials.PayloadEncrypted).Scan(&credentials.CreatedAt)
	if err != nil {
		return fmt.Errorf("PostgresVaultRepository.Save: %w", err)
	}

	return nil
}

// Returns the credential entry corresponding to the ID
func (r *PostgresVaultRepository) GetByIdAndUser(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*domain.Credentials, error) {
	
	selectCredentialsByIdAndUserQuery := `
    SELECT *
		FROM vault
		WHERE id = $1 AND user_id = $2;`

	// Get entry of a service
	var credentials domain.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByIdAndUserQuery, id, userID).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceIndex,
		&credentials.ServiceEncrypted,
		&credentials.PayloadEncrypted,
		&credentials.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		
		return nil, fmt.Errorf("PostgresVaultRepository.GetByIdAndUser: %w", err)
	}

	return &credentials, nil
}

// Returns the credential entry of the service of a user
func (r *PostgresVaultRepository) GetByServiceAndUser(ctx context.Context, serviceIndex []byte, userID uuid.UUID) (*domain.Credentials, error) {
	selectCredentialsByServiceAndUserQuery := `
    SELECT *
		FROM vault
		WHERE service_index = $1 AND user_id = $2;`

	// Get entry of a service
	var credentials domain.Credentials
	if err := r.conn.QueryRowContext(ctx, selectCredentialsByServiceAndUserQuery, serviceIndex, userID.String()).Scan(
		&credentials.ID,
		&credentials.UserID,
		&credentials.ServiceIndex,
		&credentials.ServiceEncrypted,
		&credentials.PayloadEncrypted,
		&credentials.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
	
		return nil, fmt.Errorf("PostgresVaultRepository.GetByServiceAndUser: %w", err)

	}

	return &credentials, nil
}

/* TODOs

// Returns the services associated to a user
func (r *PostgresVaultRepository) ListServicesByUser(ctx context.Context, userID int) ([]string, error) {
	//TODO

	return nil, nil
}
*/
