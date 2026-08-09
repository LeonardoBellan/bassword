package cli

import (
	"errors"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/client"
)

func RequireLogin(state *AppState) error {

	// Prompt master password
	masterPassword, err := securePrompt("Insert master password: ")
	if err != nil {
		return err
	}

	// Login
	if err := state.Client.Login(masterPassword); err != nil {        
		if errors.Is(err, client.ErrUnauthorized) {
			return fmt.Errorf("Invalid credentials. Please try again.")
		}

		return err
	}

	return nil
}
