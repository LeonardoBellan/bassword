package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewRegisterCmd(state *AppState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register <email>",
		Short: "Registers a new user",
		Long: "",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return RequireMasterPassword(state)
		},
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			
			// Get input
			email := args[0]

			err := state.Client.Register(email, state.AuthHash)
			if err != nil { return err }

			viper.Set("email", email)
			SaveConfig()


			fmt.Println("User registered successfully")
			return nil
		},
	}

	return cmd
}