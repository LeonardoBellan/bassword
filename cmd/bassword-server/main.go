package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LeonardoBellan/bassword/internal/server/api"
	"github.com/LeonardoBellan/bassword/internal/server/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/service"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
	"github.com/LeonardoBellan/bassword/internal/server/auth"

	"github.com/joho/godotenv"
)

func getDBPath() string {
	configPath := os.Getenv("DB_PATH")

	// Default
	if configPath == "" {
		configPath = ".local.db"
	}

	// If absolute path
	if filepath.IsAbs(configPath) {
		return configPath
	}

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

func getJWTExpiration() time.Duration {
	envValue := os.Getenv("JWT_EXPIRATION_TIME")

	// Default
	if envValue == "" {
		return 15*time.Minute
	}

	duration, err := time.ParseDuration(envValue)
	if err != nil {
		log.Printf("Error parsing JWT_EXPIRATION_TIME (%s), using default value: %v", envValue, err)
		return 15*time.Minute
	}

	return duration
}

func main() {

	// Environment Setup
	ctx := context.Background()
	err := godotenv.Load()
    if err != nil {
    	log.Println(".env not found, using system variables")
  }

	port := os.Getenv("PORT")

	// Token manager setup
	jwtKey := os.Getenv("JWT_KEY")
	exp := getJWTExpiration()

	tm, err := auth.NewTokenManager(jwtKey, exp)
	if err != nil {
		log.Fatalf("Error creating token manager: %v", err)
	}
	
	// DB and repository setup
	dbPath := getDBPath()
	fmt.Println(dbPath)
	conn, err := setupDB(ctx, dbPath)
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
