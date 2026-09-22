package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/server/domain"

	_ "github.com/jackc/pgx/v5/stdlib"
)


func NewPostgresDB(ctx context.Context, connString string) (*sql.DB, error){
	conn, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping failed: %w", err)
	}

	if err := InitializeDB(ctx, conn); err != nil {
		if !errors.Is(err, domain.ErrDBAlreadyInitialized) {
			conn.Close()
			return nil, fmt.Errorf("failed to initialize db: %w", err)
		}
	}

	return conn, nil
}

// InitializeDB initializes the database with the master password
func InitializeDB(ctx context.Context, conn *sql.DB) error {
	// Verify if db is already initialized
	err := verifyDB(ctx, conn)
	if err == nil {
		return domain.ErrDBAlreadyInitialized
	}
	if !errors.Is(err, domain.ErrDBNotInitialized) {
		return err
	}

	// Initialize schema
	if err := createTableUsers(ctx, conn); err != nil {
		return err
	}
	if err := createTableVault(ctx, conn); err != nil {
		return err
	}

	return nil

}

// VerifyDB verifies the presence of the tables
// Returns ErrDBNotInitialized if not initialized, nil if it has been already initialized
func verifyDB(ctx context.Context, conn *sql.DB) error {
	// Check authData presence
	var count int
    query := `
			SELECT COUNT(table_name) 
			FROM information_schema.tables 
			WHERE table_schema = 'public' 
				AND table_name IN ('users','vault')`
			
    err := conn.QueryRowContext(ctx, query).Scan(&count)
	
    if err != nil {
        return err // I/O error
    }

    // check if there are tables missing
    if count < 2 {
        return domain.ErrDBNotInitialized
    }

	return nil
}

func createTableUsers(ctx context.Context, conn *sql.DB) error {
	createUsersTableSQL := `
		CREATE TABLE IF NOT EXISTS users (
			id uuid PRIMARY KEY, 
			email text NOT NULL UNIQUE,
			secret_hash text NOT NULL,
			created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`

	/* Create table if not exists */
	if _, err := conn.ExecContext(ctx, createUsersTableSQL); err != nil {
		return err
	}

	return nil
}

func createTableVault(ctx context.Context, conn *sql.DB) error {
	createVaultTableSQL := `
		CREATE TABLE IF NOT EXISTS vault (
			id uuid PRIMARY KEY, 
			user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			service_index bytea NOT NULL,
			service_encrypted bytea NOT NULL,
			data_encrypted bytea NOT NULL,
			created_at timestamp WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, service_index)
		);`
	/* Create table if not exists */
	if _, err := conn.ExecContext(ctx, createVaultTableSQL); err != nil {
		return err
	}
	return nil
}
