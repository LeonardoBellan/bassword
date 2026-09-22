
package storage

import (
	"fmt"
	"context"
	"database/sql"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgconn"
)

type PostgresUserRepository struct {
	conn *sql.DB
}

func NewPostgresUserRepository(conn *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{conn: conn}
}

func (r *PostgresUserRepository) Save(ctx context.Context, user *domain.User) error {
	insertUserQuery := `
		INSERT INTO users(id, email, secret_hash)
		VALUES ($1, $2, $3)
		RETURNING created_at`

	err := r.conn.QueryRowContext(ctx, insertUserQuery, user.ID, user.Email, user.SecretHash).Scan(&user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr){
			if pgErr.Code == "23505" {
				return domain.ErrConflict
			} 
		}

		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("PostgresUserRepository.Save: failed to retrieve inserted user created_at")
    }

		return fmt.Errorf("PostgresUserRepository.Save: %w", err)
	}
	
	return nil
}

func (r *PostgresUserRepository) Get(ctx context.Context, id uuid.UUID) (*domain.User,error) {

	selectUserByIdQuery := `
		SELECT id, email, secret_hash
		FROM users WHERE id = $1`

	// Get user entry
	var user domain.User
	if err := r.conn.QueryRowContext(ctx, selectUserByIdQuery, id).Scan(
		&user.ID,
		&user.Email,
		&user.SecretHash,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		
		return nil, fmt.Errorf("PostgresUserRepository.Get: %w", err)
	}

	return &user, nil
}

func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User,error) {

	selectUserByEmailQuery := `
		SELECT id, email, secret_hash
		FROM users WHERE email = $1`

	// Get user entry
	var user domain.User
	if err := r.conn.QueryRowContext(ctx, selectUserByEmailQuery, email).Scan(
		&user.ID,
		&user.Email,
		&user.SecretHash,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("PostgresUserRepository.GetByEmail: %w", err)
	}

	return &user, nil
}
