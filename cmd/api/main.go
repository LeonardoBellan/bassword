package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/LeonardoBellan/bassword/internal/api"
	"github.com/LeonardoBellan/bassword/internal/handlers"
	"github.com/LeonardoBellan/bassword/internal/service"
	"github.com/LeonardoBellan/bassword/internal/storage"
)

func main() {

	// Dependencies
	ctx := context.Background()
	// TODO: environment variables for db path etc.

	// db setup
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	configDir := filepath.Join(homeDir, ".bassword")
	dbPath := filepath.Join(configDir, "passwords.db")

	conn,err := storage.OpenDB(ctx, dbPath)
	if err != nil { /* TODO Gestisci errore */ }
	defer conn.Close()

	if err := storage.InitializeDB(ctx, conn); err != nil {
		log.Println("Errore inizializzazione db", err)
	}

	// repository setup
	//userRepo := storage.NewSQLiteUserRepository(conn)
	vaultRepo := storage.NewSQLiteVaultRepository(conn)

	// service setup
	//userService := service.NewUserService(userRepo)
	vaultService := service.NewVaultService(vaultRepo)

	// handler setup
	//userHandler := service.NewUserHandler(userService)
	vaultHandler := handlers.NewVaultHandler(vaultService)

	// Router setup
	router := api.SetupRouter(ctx, /*userHandler,*/ vaultHandler)

	//TODO: Server setup (addr, handler, read/write timeout, Idle timeOut)

	// Server start
	//TODO: Background server startup with Goroutine
	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}

	//TODO: server shutdown
}