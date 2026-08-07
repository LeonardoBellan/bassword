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
			if len(args) > 0 {
				state.Email = args[0]
			}
			return RequireMasterPassword(state)
		},
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			
			err := state.Client.Register(state.Email, state.AuthHash)
			if err != nil { return err }

			viper.Set("email", state.Email)
			SaveConfig()


			fmt.Println("User registered successfully")
			return nil
		},
	}

	return cmd
}