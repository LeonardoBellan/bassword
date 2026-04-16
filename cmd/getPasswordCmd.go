package cmd

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/spf13/cobra"
)

var getPasswordCmd = &cobra.Command{
	Use:   "get [service]",
	Short: "Prints the password associated to the service",
	Args:  cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		return ensureDBOpen(ctx, dbPath)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		//Get master password
		masterPassword, err := getMasterPassword()
		defer crypto.Wipe(masterPassword)
		if err != nil { return err }

		//Get password of service
		serviceName := args[0]
		password, err := db.GetCredentialsByService(ctx,masterPassword,serviceName)
		defer crypto.Wipe(password)
		if err != nil { 
			if err == sql.ErrNoRows {
            	fmt.Println("No credentials found for: ", serviceName)
				fmt.Println("Use 'bassword add ",serviceName,"' to add these credentials")
				return nil
        	}
			return err
		}

		//Insert password into clipboard
		return copyPasswordToClipboard(password, clipboardTimeout)
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		return closeDB()
	},
}