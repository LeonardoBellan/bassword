package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrDBNotInitialized = errors.New("The database is not initialized")

func setupDB(ctx context.Context) error {
	//Create tables
	if err := createTableConfig(ctx); err != nil {
		return err
	}
	if err := createTableVault(ctx); err != nil {
		return err
	}

	//Check if DB is already present, if not return ErrDBNotInitialized
	if err := checkDBInitialization(ctx); err != nil {
		return err
	}

	return nil
}

func createTableVault(ctx context.Context) error {
	/* Create table if not exists */
	createTableQuery :=
		`CREATE TABLE IF NOT EXISTS vault (
			id INTEGER PRIMARY KEY, 
			service_name TEXT NOT NULL UNIQUE,
			username TEXT,
			encrypted_data BLOB,
			salt BLOB,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return err
	}
	return nil
}
func createTableConfig(ctx context.Context) error {
	/* Create table if not exists */
	createTableQuery :=
		`CREATE TABLE IF NOT EXISTS app_config (
			id INTEGER PRIMARY KEY CHECK (id = 1), 
			kdf_salt BLOB NOT NULL,
			canary_ciphertext BLOB NOT NULL
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return err
	}

	return nil
}

// CheckDBInitialization verifies if the database has been initialized.
// Returns ErrDBNotInitialized if not initialized, nil if it has been already initialized
func checkDBInitialization(ctx context.Context) error {
	var exists int
	query := `SELECT 1 FROM app_config WHERE id = 1`
	
	//Chack if the canary exists
	err := db.QueryRowContext(ctx,query).Scan(&exists)
	fmt.Println(err)
	if err != nil {
		//Canary not present
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDBNotInitialized
		}
		
		return fmt.Errorf("errore durante la verifica del DB: %w", err)
	}

	// DB already initialized
	return nil
}