package main

import (
	"log"
	"net/url"
	"os"

	"github.com/LeonardoBellan/bassword/internal/cli"
	"github.com/LeonardoBellan/bassword/internal/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {

	// Initialize appstate
	appState := cli.AppState{}

	rootCmd := &cobra.Command{
		Use:   "bassword",
		Short: "CLI password manager",
		Long:  "Bassword is a CLI password manager that lets the user 'safely' store and retrieve the passwords for his services.",
		
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initialize cobra config
			cli.InitConfig()

			email := viper.GetString("email")
			serverAddress := viper.GetString("server_address")
			clipboardTimeout := viper.GetDuration("clipboard_timeout")

			apiURL, err := url.Parse(serverAddress)
			if err != nil {
				log.Fatalf("Error parsing server URL: %v", err)
			}

			// Initialize appstate
			appState.Email = email
			appState.Client = client.NewClient(apiURL, email)
			appState.ClipboardTimeout = clipboardTimeout
		},
	}

	rootCmd.TraverseChildren = true

	rootCmd.AddCommand(cli.NewRegisterCmd(&appState))
	rootCmd.AddCommand(cli.NewAddCmd(&appState))
	rootCmd.AddCommand(cli.NewGetCmd(&appState))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

