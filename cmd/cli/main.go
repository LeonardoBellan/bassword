package main

import (
	"log"
	"net/url"
	"time"

	"github.com/LeonardoBellan/bassword/internal/cli"
	"github.com/LeonardoBellan/bassword/internal/client"
	"github.com/spf13/cobra"
)


func main() {

	// Initialize appstate
	// TODO - Maybe .env variables and config files (viper)
	serverAddress := "http://localhost:8080"
	apiURL, err := url.Parse(serverAddress)
	if err != nil { log.Fatalf("Error parsing server URL: %v", err)}

	appState := cli.AppState{
		EncryptionKey: nil,
		AuthHash: nil,
		Client: client.NewClient(apiURL, ""),
		ClipboardTimeout: 30*time.Second,
	}

	rootCmd := &cobra.Command{
		Use:	"bassword",
		Short:	"CLI password manager",
		Long: 	"Bassword is a CLI password manager that lets the user safely store and retrieve the passwords for his services.",
	}

	rootCmd.TraverseChildren = true
	rootCmd.PersistentFlags().DurationVar(&appState.ClipboardTimeout, "clipboard-clear", 30*time.Second, "clipboard clear timeout")

	rootCmd.AddCommand(cli.NewInitCmd(&appState))
	rootCmd.AddCommand(cli.NewAddCmd(&appState))
	rootCmd.AddCommand(cli.NewGetCmd(&appState))

	rootCmd.Execute()
}