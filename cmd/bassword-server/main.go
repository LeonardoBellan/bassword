package main

import (
	"context"
	"log"
	"fmt"
	"net/http"
	"time"

	"github.com/LeonardoBellan/bassword/internal/config"
	"github.com/LeonardoBellan/bassword/internal/server/api"
	"github.com/LeonardoBellan/bassword/internal/server/api/handlers"
	"github.com/LeonardoBellan/bassword/internal/server/service"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
	"github.com/LeonardoBellan/bassword/internal/server/auth"

	"github.com/joho/godotenv"
)

func main() {

	ctx := context.Background()

	// Environment Setup
	err := godotenv.Load()
    if err != nil {
    	log.Println(".env not found, using system variables")
  }

	dbHost := config.GetString("DB_HOST","db")
	dbPort := config.GetString("DB_PORT","5432")
	dbUser := config.GetString("DB_USER","userexample")
	dbPassword := config.GetString("DB_PASSWORD","passwordexample")
	dbName := config.GetString("DB_NAME","bassword-db")

	port := config.GetString("PORT","8080")
	jwtKey := config.GetString("JWT_KEY", "LGQDM2pMRa78eG8w/ahngaotbx4k9RkfAQ2hhjHq2Mg=") // Default key for dev
	jwtExp := config.GetDuration("JWT_EXPIRATION_TIME", 15*time.Minute)

	// Token manager setup
	tm, err := auth.NewTokenManager(jwtKey, jwtExp)
	if err != nil {
		log.Fatalf("Error creating token manager: %v", err)
	}

	// DB and repository setup
	connString := fmt.Sprintf("host=%s user=%s password=%s port=%s dbname=%s sslmode=disable", dbHost, dbUser, dbPassword, dbPort, dbName)
	conn, err := storage.NewPostgresDB(ctx, connString)
	if err != nil {
		log.Fatalf("Database setup failed: %v", err)
	}
	defer conn.Close()

	userRepo := storage.NewPostgresUserRepository(conn)
	vaultRepo := storage.NewPostgresVaultRepository(conn)

	// service setup(),
	authService := service.NewAuthService(userRepo, tm)
	vaultService := service.NewVaultService(vaultRepo)

	// handler setup
	authHandler := handlers.NewAuthHandler(authService)
	vaultHandler := handlers.NewVaultHandler(vaultService)

	// Router setup
	router := api.SetupRouter(ctx, tm, authHandler, vaultHandler)

	//TODO: Server setup (addr, handler, read/write timeout, Idle timeOut)

	// Server start
	log.Println("Starting API server on port ", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal(err)
	}
}
