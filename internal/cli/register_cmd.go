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
        Long:  "",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {

            email := args[0]

            // TODO - Email validation

            state.Client.Email = email

            // Prompt master password
            masterPassword, err := securePrompt("Insert master password: ")
            if err != nil { 
                return err 
            }

            err = state.Client.Register(masterPassword)
            if err != nil { 
                return err 
            }

            // Save email in config
            viper.Set("email", email)
            SaveConfig()

            fmt.Println("User registered successfully")
            return nil
        },
    }

    return cmd
}