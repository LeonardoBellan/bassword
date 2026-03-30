package cmd

import (
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
		return db.InitDB(dbPath)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer db.CloseDB()
		serviceName := args[0]
		entry, err := db.GetCredentialsByService(serviceName)
		if err != nil { 
			if err == sql.ErrNoRows {
            	fmt.Printf("No credentials found for: %s", serviceName)
				return nil
        	}
			return err
		}

		masterPassword, err := askPassword("Insert master password: ")
		if err != nil { return err }
		defer crypto.Wipe(masterPassword)

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
}