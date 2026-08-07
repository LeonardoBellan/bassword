package main

import (
	"log"
	"net/url"
	"os"
	"time"

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
			initConfig()

			email := viper.GetString("email")
			serverAddress := viper.GetString("server_address")
			clipboardTimeout := viper.GetDuration("clipboard_clear")

			apiURL, err := url.Parse(serverAddress)
			if err != nil {
				log.Fatalf("Error parsing server URL: %v", err)
			}

			// Initialize appstate
			appState.Email = email
			appState.Client = client.NewClient(apiURL, "")
			appState.ClipboardTimeout = clipboardTimeout
			appState.EncryptionKey = nil
			appState.AuthHash = nil
		},
	}

	rootCmd.TraverseChildren = true

	rootCmd.PersistentFlags().Duration("clipboard-clear", 30*time.Second, "clipboard clear timeout")	
	viper.BindPFlag("clipboard_clear", rootCmd.PersistentFlags().Lookup("clipboard-clear"))

	rootCmd.AddCommand(cli.NewInitCmd(&appState))
	rootCmd.AddCommand(cli.NewAddCmd(&appState))
	rootCmd.AddCommand(cli.NewGetCmd(&appState))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initConfig configura Viper per cercare file e variabili d'ambiente
func initConfig() {
	// Default values
	viper.SetDefault("server_address", "http://localhost:8080")

	// Path
	home, err := os.UserHomeDir()
	if err == nil {
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bassword")
	}

	// Env variables
	viper.SetEnvPrefix("BASSWORD")
	viper.AutomaticEnv()

	// Open config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Warning: error reading config file: %v", err)
		}
	}
}