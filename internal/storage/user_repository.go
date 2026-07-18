package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type SQLiteUserRepository struct {
	conn *sql.DB
}

func NewSQLiteUserRepository(conn *sql.DB) *SQLiteUserRepository {
	return &SQLiteUserRepository{conn: conn}
}

func (r *SQLiteUserRepository) Save(ctx context.Context, user *models.User) error {
	err := r.conn.QueryRowContext(ctx, upsertUserQuery, user.Email, user.Server_Hash, user.Server_Salt).Scan(&user.ID)
	return err
}

func (r *SQLiteUserRepository) Get(ctx context.Context, id int) (*models.User,error) {
	// Get user entry
	var user models.User
	if err := r.conn.QueryRowContext(ctx, selectUserByIdQuery, id).Scan(
		&user.ID,
		&user.Email,
		&user.Server_Hash,
		&user.Server_Salt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}
