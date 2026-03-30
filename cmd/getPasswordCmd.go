package cmd

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var getPasswordCmd = &cobra.Command{
	Use:   "get [service]",
	Short: "Prints the password associated to the service",
	Args:  cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		path,err := cmd.Flags().GetString("db-config")
		if err != nil { return err }
        return db.InitDB(path) // Initialize DB
    },
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceName := args[0]
		entry, err := db.GetCredentialsByService(serviceName)
		if err != nil { 
			if err == sql.ErrNoRows {
            	fmt.Printf("No credentials found for: %s", serviceName)
				return nil
        	}
			return err
		}

		// Get master password from user
		fmt.Printf("Insert master password: ")
		masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		defer crypto.Wipe(masterPassword) //Clean password from memory
		if err != nil { return err }
		fmt.Println()

		plaintext,err := crypto.Decrypt(entry.EncryptedData, masterPassword, entry.Salt)
		if err != nil { return err }

		//Print password
		fmt.Printf("Password for %s: %s",serviceName, plaintext)
		if err != nil { return err }
		return nil
	},
}