/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var (
	dbPath           string
	clipboardTimeout time.Duration
	rootCmd = &cobra.Command{
		Use:   "bassword",
		Short: "CLI password manager",
		Long: `Bassword is a CLI password manager that lets the user safely store and retrieve the passwords for his services using simple commands.`,
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
	rootCmd.PersistentFlags().StringVar(&dbPath, "db-config", "passwords.db", "path of the DB (default is $HOME/.passwords.db)")
	rootCmd.PersistentFlags().DurationVar(&clipboardTimeout, "clipboard-clear", 30*time.Second, "clipboard clear timeout")

	rootCmd.AddCommand(addPasswordCmd)
	rootCmd.AddCommand(getPasswordCmd)
}