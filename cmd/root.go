/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var defaultDBPath string

// rootCmd represents the base command when called without any subcommands
var (
	dbPath           string
	clipboardTimeout time.Duration
	rootCmd = &cobra.Command{
		Use:   "bassword",
		Short: "CLI password manager",
		Long: `Bassword is a CLI password manager that lets the user safely store and retrieve the passwords for his services.`,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// flags and configuration settings
func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	configDir := filepath.Join(homeDir, ".bassword")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		defaultDBPath = filepath.Join(homeDir, ".passwords.db")
	} else {
		defaultDBPath = filepath.Join(configDir, "passwords.db")
	}

	rootCmd.TraverseChildren = true
	rootCmd.PersistentFlags().StringVar(&dbPath, "db-config", defaultDBPath, "path of the DB (default is $HOME/.bassword/passwords.db)")
	rootCmd.PersistentFlags().DurationVar(&clipboardTimeout, "clipboard-clear", 30*time.Second, "clipboard clear timeout")
	
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addPasswordCmd)
	rootCmd.AddCommand(getPasswordCmd)
}