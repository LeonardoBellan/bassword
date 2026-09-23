package storage_test

import (
	"context"
	"fmt"
	"database/sql"
	"errors"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
	"github.com/LeonardoBellan/bassword/internal/config"

	"github.com/joho/godotenv"
)

// setupdTestDB connects to a temporary uninitialized db
// Returns the sql connection and the database connectionString
func setupTestDB(ctx context.Context,t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	err := godotenv.Load("../../../.env")
    if err != nil {
    	t.Log(".env not found, using default values")
  }

	dbHost := config.GetString("TEST_DB_HOST","localhost")
	dbPort := config.GetString("TEST_DB_PORT","5432")
	dbUser := config.GetString("TEST_DB_USER","usertest")
	dbPassword := config.GetString("TEST_DB_PASSWORD","passwordtest")
	dbName := config.GetString("TEST_DB_NAME","bassword-db")
	connString := fmt.Sprintf("host=%s user=%s password=%s port=%s dbname=%s sslmode=disable", dbHost, dbUser, dbPassword, dbPort, dbName)

	// Open connection
	conn, err := sql.Open("pgx", connString)
	if err != nil {
		t.Fatalf("Error opening db: %v", err)
	}

	if err := conn.PingContext(ctx); err != nil {
		t.Fatalf("Error connecting to db: %v", err)
	}

	_, err = conn.ExecContext(ctx, "DROP TABLE IF EXISTS users, vault CASCADE")
	if err != nil {
		t.Fatalf("Failed to clean database tables: %v", err)
	}
	
	// Close connection
	t.Cleanup(func() {
		conn.ExecContext(ctx, "DROP TABLE IF EXISTS users, vault CASCADE")
		conn.Close()
	})
	
	return conn, connString
}

// setupdInitializedTestDB initializes a database
// Returns the connection and path
func setupInitializedTestDB(ctx context.Context, t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	conn, connString := setupTestDB(ctx,t)
	if err := storage.InitializeDB(ctx,conn); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}
	return conn, connString
}

func TestInitializeDB(t *testing.T) {
	t.Run("Success_First_Initialization", func (t *testing.T) {
		ctx := context.Background()
		conn, _ := setupTestDB(ctx,t)

		if err := storage.InitializeDB(ctx,conn); err != nil {
			t.Fatalf("InitializeDB failed: %v", err)
		}

		// Check tables
		_, err := conn.Exec("INSERT INTO users (id, email, secret_hash) VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479','test_user', 'test_hash')")
    	if err != nil {
      	t.Errorf("Could not insert into 'users' after initialization: %v", err)
    	}

    	_, err = conn.Exec("INSERT INTO vault (id, service_index, service_encrypted, data_encrypted, user_id) VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479','service_index','service_encrypted','encrypted-secret','f47ac10b-58cc-4372-a567-0e02b2c3d479')")
    	if err != nil {
        t.Errorf("Could not insert into 'vault' after initialization: %v", err)
    	}
	})

	t.Run("Failure_Second_Initialization", func(t * testing.T){
		ctx := context.Background()
		conn, _ := setupInitializedTestDB(ctx,t)

		if err := storage.InitializeDB(ctx,conn); !errors.Is(err,domain.ErrDBAlreadyInitialized) {
			t.Errorf("Expected error '%v', got '%v'", domain.ErrDBAlreadyInitialized,err)
		}
	})

	t.Run("Failure_Context_Cancelled", func(t *testing.T){
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Setup with base context
		conn, _ := setupTestDB(context.Background(), t) 

		// Initialization with cancelled context
		err := storage.InitializeDB(ctx, conn)

    if err == nil {
      t.Error("Expected InitializeDB to fail with a cancelled context, got nil")
    } else if !errors.Is(err, context.Canceled) {
    	t.Errorf("Expected error '%v', got '%v'", context.Canceled, err)
   	}
	})
}

func TestNewPostgresDB(t *testing.T) {
	t.Run("Success_After_Initialization", func(t *testing.T) {
		ctx := context.Background()
		_, connString := setupInitializedTestDB(ctx,t)

		conn, err := storage.NewPostgresDB(ctx, connString)
		if err != nil { t.Fatalf("Could not open initialized db, got: %v", err) }
		t.Cleanup(func() { conn.Close() })

		// Check connection
		if err := conn.PingContext(ctx); err != nil {
			t.Fatalf("Could not connect to db: %v", err)
		}
	})
	
	t.Run("Failure_Context_Cancelled", func(t *testing.T){
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Setup with base context
		_, connString := setupInitializedTestDB(context.Background(), t) 

		// Initialization with cancelled context
		conn, err := storage.NewPostgresDB(ctx, connString)

		if conn != nil { t.Cleanup(func() { conn.Close() }) }
		if err == nil {
    	t.Error("Expected to fail with a cancelled context, got nil")
    } else if !errors.Is(err, context.Canceled) {
    	t.Errorf("Expected error '%v', got '%v'", context.Canceled, err)
		}
	})
}
