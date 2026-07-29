package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/LeonardoBellan/bassword/internal/api"
	"github.com/LeonardoBellan/bassword/internal/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/crypto"
	"github.com/LeonardoBellan/bassword/internal/domain"
	"github.com/LeonardoBellan/bassword/internal/service"
	"github.com/LeonardoBellan/bassword/internal/storage"
	"github.com/joho/godotenv"
)

func main() {

	// Environment Setup
	ctx := context.Background()
	err := godotenv.Load()
    if err != nil {
    	log.Fatal(err)
    }

	// Token manager setup
	jwtKey := os.Getenv("JWT_KEY")
	tm := crypto.NewTokenManager(jwtKey)

	// determine db path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	configPath := os.Getenv("DB_PATH")
	dbPath := filepath.Join(homeDir, configPath)

	// db connection
	conn,err := storage.OpenDB(ctx, dbPath)
	if err != nil { log.Fatalf("failed to open database: %v", err) }
	defer conn.Close()

	if err := storage.InitializeDB(ctx, conn); err != nil {
		if !errors.Is(err, domain.ErrDBAlreadyInitialized) {
			log.Fatalf("failed to initialize db: %v", err)
		}
		
		log.Print("Db already initialized")
	}

	// repository setup
	userRepo := storage.NewSQLiteUserRepository(conn)
	vaultRepo := storage.NewSQLiteVaultRepository(conn)

	// service setup
	authService := service.NewAuthService(userRepo, tm)
	vaultService := service.NewVaultService(vaultRepo)

	// handler setup
	authHandler := handlers.NewAuthHandler(authService)
	vaultHandler := handlers.NewVaultHandler(vaultService)

	// Router setup
	router := api.SetupRouter(ctx, tm, authHandler, vaultHandler)

	//TODO: Server setup (addr, handler, read/write timeout, Idle timeOut)

	// Server start
	//TODO: Background server startup with Goroutine
	log.Println("Starting API server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}

	//TODO: server shutdown
}