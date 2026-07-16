package storage

import (
	"context"
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
)

var ErrDBNotInitialized = errors.New("Database is not initialized")
var ErrDBAlreadyInitialized = errors.New("Database is already initialized")

func OpenDB(ctx context.Context, dbPath string) (*sql.DB, error) {
	// Open db connection
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {	return nil,err }

	// Verify connection and initialization
	if err := conn.PingContext(ctx); err != nil { 
		conn.Close()
		return nil,err
	}

	return conn,nil
}

// InitializeDB initializes the database with the master password
func InitializeDB(ctx context.Context, conn *sql.DB, masterPassword []byte) error {
	// Verify if db is already initialized
	err := verifyDB(ctx, conn)
	if err == nil {
		return ErrDBAlreadyInitialized
	}
	if !errors.Is(err, ErrDBNotInitialized) {
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

// VerifyDB verifies the presence of the db tables
// Returns ErrDBNotInitialized if not initialized, nil if it has been already initialized
func verifyDB(ctx context.Context, conn *sql.DB) error {
	// Check authData presence
	var count int
    query := `
		SELECT COUNT(name) 
		FROM sqlite_master 
		WHERE type='table' 
			AND name IN ('users','vault')`
    
    err := conn.QueryRowContext(ctx, query).Scan(&count)
	
    if err != nil {
        return err // I/O error
    }

    // db not initialized
    if count < 2 {
        return ErrDBNotInitialized
    }

	return nil
}

func createTableUsers(ctx context.Context, conn *sql.DB) error {
	/* Create table if not exists */
	if _, err := conn.ExecContext(ctx, createUsersTableSQL); err != nil {
		return err
	}

	return nil
}

func createTableVault(ctx context.Context, conn *sql.DB) error {
	/* Create table if not exists */
	if _, err := conn.ExecContext(ctx, createVaultTableSQL); err != nil {
		return err
	}
	return nil
}
