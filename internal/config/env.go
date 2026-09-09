package config

import (
	"os"
	"time"
	"log"
)

func GetString(key string, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}

	return fallback
}

func GetDuration(key string, fallback time.Duration) time.Duration {
	envValue := os.Getenv(key)
	if envValue == "" {
		return fallback
	}

	duration, err := time.ParseDuration(envValue)
	if err != nil {
		log.Printf("Warning: invalid duration for %s (%s), using default: %v", key, envValue, fallback)
		return fallback
	}

	return duration
}
