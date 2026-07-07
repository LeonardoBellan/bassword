package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/crypto"
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
	if _, err := db.ExecContext(ctx, createVaultTableSQL); err != nil {
		return err
	}
	return nil
}
func createTableConfig(ctx context.Context) error {
	/* Create table if not exists */
	if _, err := db.ExecContext(ctx, createConfigTableSQL); err != nil {
		return err
	}

	return nil
}

// InitializeDB initializes the database with the master password
func InitializeDB(ctx context.Context, masterPassword []byte) error {
	return insertCanary(ctx, masterPassword)
}

func insertCanary(ctx context.Context, masterPassword []byte) error {
	defer crypto.Wipe(masterPassword)
	salt := make([]byte, 16)
	rand.Read(salt)
	canaryCiphertext, err := crypto.Encrypt([]byte(canaryText), masterPassword, salt)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, upsertCanaryQuery, canaryID, salt, canaryCiphertext)
	if err != nil {
		return err
	}

	return nil
}

// CheckDBInitialization verifies if the database has been initialized (There is a Canary)
// Returns ErrDBNotInitialized if not initialized, nil if it has been already initialized
func checkDBInitialization(ctx context.Context) error {
	var exists int
	query := selectCanaryQuery
	
	//Check if the canary exists
	err := db.QueryRowContext(ctx, query, canaryID).Scan(&exists)
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