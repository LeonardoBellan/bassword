package storage

import (
	"context"
	"database/sql"

	"github.com/LeonardoBellan/bassword/internal/models"
)

type UserRepository struct {
	conn *sql.DB
}

// Dependency injection
func NewUserRepository(conn *sql.DB) *UserRepository {
	return &UserRepository{conn: conn}
}

func (r *UserRepository) AddUser(ctx context.Context, user *models.User) error {
	err := r.conn.QueryRowContext(ctx, upsertUserQuery, user.Email, user.Server_Hash, user.Server_Salt).Scan(&user.ID)
	return err
}

func (r *UserRepository) GetUser(ctx context.Context, ID int) (models.User,error) {
	// Get user entry
	var user models.User
	if err := r.conn.QueryRowContext(ctx, selectUserByIdQuery, ID).Scan(
		&user.ID,
		&user.Email,
		&user.Server_Hash,
		&user.Server_Salt,
	); err != nil {
		return models.User{}, err
	}

	return user, nil
}
