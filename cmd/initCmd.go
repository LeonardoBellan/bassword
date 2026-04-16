package cmd

import (
	"context"
	"errors"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database with master password",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Ask for master password
		masterPassword, err := askPassword("Insert master password: ")
		if err != nil {
			return err
		}
		defer crypto.Wipe(masterPassword)

		// Open DB (creates tables if not exist)
		err = db.OpenDB(ctx, dbPath)
		if err != nil && !errors.Is(err, db.ErrDBNotInitialized) {
			return err
		}

		// Initialize with canary
		if err := db.InitializeDB(ctx, masterPassword); err != nil {
			return err
		}

		return nil
	},
}