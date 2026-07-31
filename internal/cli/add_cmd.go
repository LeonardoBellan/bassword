package cli

import (
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/client"
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"

	"github.com/spf13/cobra"
)

func NewAddCmd(state *AppState) *cobra.Command {

	var isRandom bool
	var length int

	cmd := &cobra.Command{
		Use:   "add <service> <username>",
		Short: "Save or update a password for a service",
		Long: `Save or update a password for a service.

			By default, the command prompts for the password interactively.
			Use --random to generate a secure random password instead, and --length to set its size.`,
		Example: `  bassword add github alice
  				bassword add github alice --random
  				bassword add github alice --random --length 24`,
		Args:  cobra.ExactArgs(2),
		PreRunE: func(cmd *cobra.Command, args []string) error {

			// Validate flag parameters
			lengthFlagChanged := cmd.Flags().Changed("length")
			if lengthFlagChanged && !isRandom {
				return fmt.Errorf("--length requires --random")
			}
			if length <= 0 {
				return fmt.Errorf("--length must be greater than 0")
			}

			return RequireLogin(state)
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			// Get inputs
			serviceName := args[0]
			username := args[1]

			//Get service password from user
			var plaintext []byte
			var err error
			if isRandom {
				plaintext, err = generateRandomPassword(length)
			} else{
				plaintext, err = getPlaintextPassword(serviceName)
			}
			defer crypto.Wipe(plaintext) //Clean password from memory
			if err != nil { return err }

			credentials, err := client.NewCredentials(username, plaintext)
			if err != nil { return err }
			state.Client.AddPassword(state.EncryptionKey, serviceName, credentials)

			//Copy password in clipboard
			fmt.Println("Credentials successfully created!")
			fmt.Println("Username: ", credentials.Username)
			return copyPasswordToClipboard(plaintext, state.ClipboardTimeout)
		},
	}

	// Flags
	cmd.Flags().BoolVarP(&isRandom, "random", "r", false, "generate a random password instead of prompting")
	cmd.Flags().IntVarP(&length, "length", "l", 16, "length of the generated password (requires --random and must be greater than 0)")

	return cmd
}