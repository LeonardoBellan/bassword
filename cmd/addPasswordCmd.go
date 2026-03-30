package cmd

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/LeonardoBellan/bassword/internal/models"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var addPasswordCmd = &cobra.Command{
	Use:   "add [service] [username]",
	Short: "Save or updates a password for a service",
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		path,err := cmd.Flags().GetString("db-config")
		if err != nil { return err }
        return db.InitDB(path) // Initialize DB
    },
	RunE: func(cmd *cobra.Command, args []string) error {
		//Fill new entry fields
		var newEntry models.CredentialEntry
		newEntry.ServiceName = args[0]
		newEntry.Username = args[1]
		newEntry.Salt = make([]byte, 16)
		rand.Read(newEntry.Salt)

		// Get master password from user
		fmt.Printf("Insert master password: ")
		masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		defer crypto.Wipe(masterPassword) //Clean password from memory
		if err != nil { return err }
		fmt.Println()

		//Get service password from user and encrypt it
		fmt.Printf("Insert password for %s: ", newEntry.ServiceName)
		plaintext, err := term.ReadPassword(int(os.Stdin.Fd()))
		defer crypto.Wipe(plaintext) //Clean password from memory
		if err != nil {
			return err
		}
		fmt.Println()

		newEntry.EncryptedData, err = crypto.Encrypt(plaintext, masterPassword, newEntry.Salt)
		if err != nil { return err }

		//Add or update password in DB
		err = db.AddPassword(&newEntry)
		if err != nil { return err }
		return nil
	},
}