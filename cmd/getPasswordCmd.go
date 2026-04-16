package cmd

import (
	"context"
	"database/sql"
	"errors"
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

			err := db.OpenDB(ctx,dbPath)
			if err != nil {
				if !errors.Is(err, db.ErrDBNotInitialized) {
					return err
				}
				return fmt.Errorf("DB not initialized, run bassword init")
			}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		//Get master password
		masterPassword, err := askPassword("Insert master password: ")
		defer crypto.Wipe(masterPassword)
		if err != nil { return err }

		//Get credentials info
		serviceName := args[0]
		entry, err := db.GetCredentialsByService(ctx,serviceName)
		if err != nil { 
			if err == sql.ErrNoRows {
            	fmt.Println("No credentials found for: ", serviceName)
				fmt.Print("Use 'bassword add ",serviceName,"' to add these credentials\n")
				return nil
        	}
			return err
		}

		plaintext,err := crypto.Decrypt(entry.EncryptedData, masterPassword, entry.Salt)
		if err != nil { return err }
		defer crypto.Wipe(plaintext)

		//Insert password in clipboard
		writeDone,err := copyToClipboardWithTimeout(plaintext, clipboardTimeout)
		if err != nil { return err }

		fmt.Println("Password inserted into clipboard, elapses in ", clipboardTimeout)
		<-writeDone
		return nil
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		if err := db.CloseDB(); err != nil {
			return err
		}
		return nil
	},
}