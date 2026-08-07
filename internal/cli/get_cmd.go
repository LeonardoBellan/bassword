package cli

import (
	"fmt"
	"time"

	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)


func NewGetCmd(state *AppState) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "get <service>",
		Short: "Prints the password associated to the service",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {

			cmd.SilenceUsage = true
			return RequireLogin(state)
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			//Get inputs
			serviceName := args[0]

			credentials, err := state.Client.GetPassword(state.EncryptionKey, serviceName)
			defer crypto.Wipe(credentials.Password) //Clean password from memory
			if err != nil { return err }

			// Pass credentials to user
			fmt.Println("Username:", credentials.Username)
			return copyPasswordToClipboard(credentials.Password, state.ClipboardTimeout)
		},
	}

	cmd.Flags().Duration("clipboard-clear", 30*time.Second, "clipboard clear timeout")	
	viper.BindPFlag("clipboard_timeout", cmd.Flags().Lookup("clipboard-clear"))

	return cmd
}