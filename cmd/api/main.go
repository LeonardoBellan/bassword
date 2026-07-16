package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/LeonardoBellan/bassword/internal/api"
	"github.com/LeonardoBellan/bassword/internal/db"
)

func main() {

	// Dependencies
	// TODO: environment variables
	
	//TODO: DB SETUP
	//TODO: SERVICE SETUP es. service.NewCredentialService(db)
	//TODO: HANDLER SETUP es. handlers.NewCredentialHandler(credService)

	// Use same default path as CLI
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	configDir := filepath.Join(homeDir, ".bassword")
	dbPath := filepath.Join(configDir, "passwords.db")

	// Try to open DB; if not initialized, fail with clear message
	ctx := context.Background()
	if err := db.OpenDB(ctx, dbPath); err != nil {
		if err == db.ErrDBNotInitialized {
			log.Fatalf("Database not initialized at %s. Run: bassword init --db-config %s\n", dbPath, dbPath)
		}
		log.Fatalf("Failed to open database: %v\n", err)
	}
	defer db.CloseDB()

	// Router setup
	router := api.SetupRouter(credHandler)

	//TODO: Server setup (addr, handler, read/write timeout, Idle timeOut)

	// Server start
	//TODO: Background server startup with Goroutine
	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}

	//TODO: server shutdown and db close
}