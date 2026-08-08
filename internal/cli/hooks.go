package cli

import (
	"errors"
	"fmt"

	"github.com/LeonardoBellan/bassword/internal/client"
	"github.com/LeonardoBellan/bassword/internal/shared/crypto"
)

func PrepareRegistration(state *AppState) error {

	// Prompt master password
	masterPassword, err := securePrompt("Insert master password: ")
	if err != nil { return err }

	state.Client.PrepareRegistration(masterPassword, []byte(state.Email))
	
	return nil
}

func RequireLogin(state *AppState) error {

	// Already logged
	if state.Client.IsLogged() {
		return nil
	}

	if state.Email == "" {
		return client.ErrNotRegistered
	}

	// Prompt master password
	masterPassword, err := securePrompt("Insert master password: ")
	if err != nil {
		return err
	}

	// Login
	if err := state.Client.Login(masterPassword, state.Email); err != nil {        
		if errors.Is(err, client.ErrUnauthorized) {
			return fmt.Errorf("Invalid credentials. Please try again.")
		}

		return err
	}

	return nil
}
