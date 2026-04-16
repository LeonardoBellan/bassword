package cmd

import (
	"context"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/LeonardoBellan/bassword/internal/models"
	"github.com/spf13/cobra"
)

var addPasswordCmd = &cobra.Command{
	Use:   "add [service] [username]",
	Short: "Save or updates a password for a service",
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		return ensureDBOpen(ctx, dbPath)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Fill new entry fields
		var newEntry models.CredentialEntry
		newEntry.ServiceName = args[0]
		newEntry.Username = args[1]

		//Get master password
		masterPassword, err := getMasterPassword()
		defer crypto.Wipe(masterPassword)
		if err != nil { return err }

		//Get service password
		plaintext, err := askPassword(fmt.Sprintf("Insert password for %s: ", newEntry.ServiceName))
		if err != nil { return err }
		defer crypto.Wipe(plaintext) //Clean password from memory

		err = db.AddPassword(ctx,masterPassword,plaintext,&newEntry)
		if err != nil { return err }

		//Copy password in clipboard
		return copyPasswordToClipboard(plaintext, clipboardTimeout)
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		return closeDB()
	},
}