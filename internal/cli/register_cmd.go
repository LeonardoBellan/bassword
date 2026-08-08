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
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			state.Email = args[0]

			// TODO - Email validation

			// Prompt master password
			masterPassword, err := securePrompt("Insert master password: ")
			if err != nil { return err }

			err := state.Client.Register(masterPassword, state.Email)
			if err != nil { return err }

			viper.Set("email", state.Email)
			SaveConfig()

			fmt.Println("User registered successfully")
			return nil
		},
	}

	return cmd
}
