package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/domain"
)

type SQLiteUserRepository struct {
	conn *sql.DB
}

func NewSQLiteUserRepository(conn *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{conn: conn}
}

func (r *SQLiteUserRepository) Save(ctx context.Context, user *domain.User) error {
	err := r.conn.QueryRowContext(ctx, upsertUserQuery, user.Email, user.ServerHash, user.ServerSalt).Scan(&user.ID)
	return err
}

func (r *SQLiteUserRepository) Get(ctx context.Context, id int) (*domain.User,error) {
	// Get user entry
	var user domain.User
	if err := r.conn.QueryRowContext(ctx, selectUserByIdQuery, id).Scan(
		&user.ID,
		&user.Email,
		&user.ServerHash,
		&user.ServerSalt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *SQLiteUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User,error) {
	// Get user entry
	var user domain.User
	if err := r.conn.QueryRowContext(ctx, selectUserByEmailQuery, email).Scan(
		&user.ID,
		&user.Email,
		&user.ServerHash,
		&user.ServerSalt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &user, nil
}
