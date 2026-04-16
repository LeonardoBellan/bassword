package cmd

import (
	"context"
	"crypto/rand"
	"errors"
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

		//Fill new entry fields
		var newEntry models.CredentialEntry
		newEntry.ServiceName = args[0]
		newEntry.Username = args[1]
		newEntry.Salt = make([]byte, 16)
		if _, err := rand.Read(newEntry.Salt); err != nil {
			return err
		}
		
		plaintext, err := askPassword(fmt.Sprintf("Insert password for %s: ", newEntry.ServiceName))
		if err != nil { return err }
		defer crypto.Wipe(plaintext) //Clean password from memory

		//Copy password in clipboard
		writeDone,err := copyToClipboardWithTimeout(plaintext, clipboardTimeout)
		if err != nil {
			return err
		}

		//Add encrypted password to DB
		newEntry.EncryptedData, err = crypto.Encrypt(plaintext, masterPassword, newEntry.Salt)
		if err != nil { return err }
		err = db.AddPassword(ctx, &newEntry)
		if err != nil { return err }

		fmt.Println("Added password and inserted into clipboard, elapses in ", clipboardTimeout)
		<-writeDone	//Wait for clipboard clearing
		return nil
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		if err := db.CloseDB(); err != nil {
			return err
		}
		return nil
	},
}