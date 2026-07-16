package main

import (
	"context"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/db"
	"github.com/LeonardoBellan/bassword/internal/models"
	"github.com/spf13/cobra"
)

var (
	random bool
	length int
)

var addPasswordCmd = &cobra.Command{
	Use:   "add <service> <username>",
	Short: "Save or update a password for a service",
	Long: `Save or update a password for a service.

By default, the command prompts for the password interactively.
Use --random to generate a secure random password instead, and --length to set its size.`,
	Example: `  bassword add github alice
  bassword add github alice --random
  bassword add github alice --random --length 24`,
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		var err error

		random, err = cmd.Flags().GetBool("random")
		if err != nil {
			return err
		}

		length, err = cmd.Flags().GetInt("length")
		if err != nil {
			return err
		}

		lengthFlagChanged := cmd.Flags().Changed("length")
		if lengthFlagChanged && !random {
			return fmt.Errorf("--length requires --random")
		}
		if length <= 0 {
			return fmt.Errorf("--length must be greater than 0")
		}

		ctx := context.Background()
		return ensureDBOpen(ctx, dbPath)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		// Fill new entry fields
		var newEntry models.CredentialEntry
		newEntry.ServiceName = args[0]
		newEntry.Username = args[1]

		//Get master password
		masterPassword, err := getMasterPassword()
		defer crypto.Wipe(masterPassword)
		if err != nil { return err }

		//Get service password
		var plaintext []byte
		if random {
			plaintext, err = generateRandomPassword(length)
		} else{
			plaintext, err = getPlaintextPassword(newEntry.ServiceName)
		}
		defer crypto.Wipe(plaintext) //Clean password from memory
		if err != nil { return err }

		//TODO: use client function using API endpoints
		err = db.AddPassword(ctx,masterPassword,plaintext,&newEntry)
		if err != nil { return err }

		//Copy password in clipboard
		return copyPasswordToClipboard(plaintext, clipboardTimeout)
	},
	PostRunE: func(cmd *cobra.Command, args []string) error {
		if err := closeDB(); err != nil {
			return err
		}
		return nil
	},
}
func init() {
	addPasswordCmd.Flags().BoolP("random", "r", false, "generate a random password instead of prompting")
	addPasswordCmd.Flags().IntP("length", "l", 16, "length of the generated password (requires --random and must be greater than 0)")
	rootCmd.AddCommand(addPasswordCmd)
}