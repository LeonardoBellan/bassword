package cli

import (
	"github.com/spf13/cobra"
)

func NewInitCmd(state *AppState) *cobra.Command {
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

			return nil
		},
	}

	return cmd
}