package cli

import (
	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/spf13/cobra"
)


func NewGetCmd(state *AppState) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "get <service>",
		Short: "Prints the password associated to the service",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return RequireLogin(state)
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			//Get inputs
			serviceName := args[0]

			_, plaintext, err := state.Client.GetPassword(state.EncryptionKey, serviceName)
			defer crypto.Wipe(plaintext) //Clean password from memory
			if err != nil { return err }

			//Copy password in clipboard
			return copyPasswordToClipboard(plaintext, state.ClipboardTimeout)
		},
	}

	return cmd
}