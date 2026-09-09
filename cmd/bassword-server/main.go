package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LeonardoBellan/bassword/internal/config"
	"github.com/LeonardoBellan/bassword/internal/server/api"
	"github.com/LeonardoBellan/bassword/internal/server/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
	"github.com/LeonardoBellan/bassword/internal/server/auth"

	"github.com/joho/godotenv"
)

func getDBPath() string {
	configPath := config.GetString("DB_PATH", "./data/bassword.db")

	// Absolute path
	if filepath.IsAbs(configPath) {
		return configPath
	}

	// Relative path (HOME)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	
	return filepath.Join(homeDir, configPath)
}

func setupDB(ctx context.Context, path string) (*sql.DB, error){
	conn,err := storage.OpenDB(ctx, path)
	if err != nil { log.Fatalf("failed to open database: %v", err) }

	if err := storage.InitializeDB(ctx, conn); err != nil {
		if !errors.Is(err, domain.ErrDBAlreadyInitialized) {
			conn.Close()
			log.Fatalf("failed to initialize db: %v", err)
		}
		
		log.Print("Db already initialized")
	}

	return conn, nil
}

func main() {

	// Environment Setup
	err := godotenv.Load()
    if err != nil {
    	log.Println(".env not found, using system variables")
  }

	dbPath := getDBPath()
	port := config.GetString("PORT","8080")
	jwtKey := config.GetString("JWT_KEY", "LGQDM2pMRa78eG8w/ahngaotbx4k9RkfAQ2hhjHq2Mg=") // Default key for dev
	jwtExp := config.GetDuration("JWT_EXPIRATION_TIME", 15*time.Minutes)

	// Token manager setup
	tm, err := auth.NewTokenManager(jwtKey, jwtExp)
	if err != nil {
		log.Fatalf("Error creating token manager: %v", err)
	}
	
	// DB and repository setup
	conn, err := setupDB(context.Background(), dbPath)
	if err != nil {
		log.Fatalf("Database setup failed: %v", err)
	}

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
	log.Println("Starting API server on port ", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal(err)
	}

	//TODO: server shutdown
}
