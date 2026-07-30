package storage_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/LeonardoBellan/bassword/internal/server/domain"
	"github.com/LeonardoBellan/bassword/internal/server/storage"
)

// setupdTestDB creates and connects to a temporary uninitialized db
// Returns the connection and path
func setupTestDB(ctx context.Context,t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	// temporary db file
	dbPath := filepath.Join(t.TempDir(), "test.db")
	
	conn, err := storage.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("Error opening db in %s: %v", dbPath, err)
	}

	// Check connection
	if err := conn.PingContext(ctx); err != nil {
		t.Fatalf("Error connecting to db: %v", err)
	}
	
	// Close connection
	t.Cleanup(func() {
		conn.Close()
	})
	
	return conn, dbPath
}

// setupdInitializedTestDB initializes and connects to a temporary db
// Returns the connection and path
func setupInitializedTestDB(ctx context.Context, t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	conn, path := setupTestDB(ctx,t)
	if err := storage.InitializeDB(ctx,conn); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}
	return conn, path
}

func TestInitializeDB(t *testing.T) {
	t.Run("Success_First_Initialization", func (t *testing.T) {
		ctx := context.Background()
		conn, _ := setupTestDB(ctx,t)

		if err := storage.InitializeDB(ctx,conn); err != nil {
			t.Fatalf("InitializeDB failed: %v", err)
		}

		// Check tables
		_, err := conn.Exec("INSERT INTO users (email, Server_Hash, Server_Salt) VALUES ('test_user',1,1)")
    	if err != nil {
     	   t.Errorf("Could not insert into 'users' after initialization: %v", err)
    	}

    	_, err = conn.Exec("INSERT INTO vault (service_name, encrypted_data, user_id) VALUES ('service','encrypted-secret',1)")
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

func TestOpenDB(t *testing.T) {
	t.Run("Success_After_Initialization", func(t *testing.T) {
		ctx := context.Background()
		_, path := setupInitializedTestDB(ctx,t)

		conn, err := storage.OpenDB(ctx,path)
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
		_, path := setupInitializedTestDB(context.Background(), t) 

		// Initialization with cancelled context
		conn, err := storage.OpenDB(ctx,path)

		if conn != nil { t.Cleanup(func() { conn.Close() }) }
		if err == nil {
        	t.Error("Expected OpenDB to fail with a cancelled context, got nil")
    	} else if !errors.Is(err, context.Canceled) {
       		t.Errorf("Expected error '%v', got '%v'", context.Canceled, err)
   		}
	})
}