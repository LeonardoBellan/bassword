package cmd

import (
	"crypto/rand"
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
		return db.InitDB(dbPath)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer db.CloseDB()
		
		//Fill new entry fields
		var newEntry models.CredentialEntry
		newEntry.ServiceName = args[0]
		newEntry.Username = args[1]
		newEntry.Salt = make([]byte, 16)
		if _, err := rand.Read(newEntry.Salt); err != nil {
			return err
		}

		// Get master password from user
		masterPassword, err := askPassword("Insert master password: ")
		if err != nil { return err }
		defer crypto.Wipe(masterPassword) //Clean password from memory

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
		err = db.AddPassword(&newEntry)
		if err != nil { return err }

		fmt.Println("Added password and inserted into clipboard, elapses in ",clipboardTimeout)
		<-writeDone	//Wait for clipboard clearing
		return nil
	},
}