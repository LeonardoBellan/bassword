package cli

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

func InitConfig() {
	// Default values
	viper.SetDefault("server_address", "http://localhost:8080")
	viper.SetDefault("clipboard_timeout", 30*time.Second)

	// Open config file
	home, err := os.UserHomeDir()
	if err == nil {
		viper.AddConfigPath(filepath.Join(home, ".bassword"))
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Env variables
	viper.SetEnvPrefix("BASSWORD")
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Warning: error reading config file: %v", err)
		}
	}
}

func SaveConfig() error {
	// Write in config file
	if err := viper.WriteConfig(); err == nil {
		return nil
	}

	// Create config file if it does not exist
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find home directory: %w", err)
	}

	configDir := filepath.Join(home, ".bassword")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")

	if err := viper.WriteConfigAs(configPath); err != nil {
		return fmt.Errorf("error during configuration creation: %w", err)
	}

	return nil
}