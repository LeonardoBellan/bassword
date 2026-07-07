package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database with master password",
	Long: `Initialize the local database and store a verification canary encrypted with the provided master password.

This command will create the required tables (if missing) and store a KDF salt and an encrypted canary in the
app_config table. The canary plaintext is "VERIFICATION_OK" and is used to verify the correctness of the
master password on subsequent invocations.

WARNING: Re-running this command with a different master password will overwrite the stored canary and salt.
Existing encrypted entries in the vault will no longer be decryptable unless re-encrypted with the new master
password. Back up your database before reinitializing.
`,
	Example: "bassword init --db-config /path/to/passwords.db",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Open DB (creates tables if not exist)
		err := db.OpenDB(ctx, dbPath)
		if err != nil && !errors.Is(err, db.ErrDBNotInitialized) {
			return err
		}

		// If DB already initialized, ask for user confirmation before overwriting canary
		if err == nil {
			reader := bufio.NewReader(os.Stdin)
			fmt.Fprintf(os.Stderr, "Database already initialized at %s. Reinitializing will overwrite the stored canary and salt, making existing entries undecryptable. Proceed? (y/N): ", dbPath)
			resp, _ := reader.ReadString('\n')
			resp = strings.TrimSpace(resp)
			if strings.ToLower(resp) != "y" && strings.ToLower(resp) != "yes" {
				fmt.Fprintln(os.Stderr, "Initialization aborted.")
				return nil
			}
		}

		// Ask for master password
		masterPassword, err := getMasterPassword()
		if err != nil {
			return err
		}
		defer crypto.Wipe(masterPassword)

		// Initialize with canary
		if err := db.InitializeDB(ctx, masterPassword); err != nil {
			return err
		}

		fmt.Printf("Database initialized at %s\n", dbPath)
		return nil
	},
}