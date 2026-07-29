package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/mattn/go-sqlite3"
)

type SQLiteUserRepository struct {
	conn *sql.DB
}

func NewSQLiteUserRepository(conn *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{conn: conn}
}

func (r *SQLiteUserRepository) Save(ctx context.Context, user *domain.User) error {
	err := r.conn.QueryRowContext(ctx, insertUserQuery, user.ID, user.Email, user.ServerHash, user.ServerSalt).Scan(&user.CreatedAt)
	if err != nil {
		var sqliteErr sqlite3.Error
        if errors.As(err, &sqliteErr) {
			if sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
				return domain.ErrConflict
         	}
        }

		if errors.Is(err, sql.ErrNoRows) {
            return errors.New("failed to retrieve inserted user created_at")
        }

		return err
	}
	
	return nil
}

func (r *SQLiteUserRepository) Get(ctx context.Context, id string) (*domain.User,error) {
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
