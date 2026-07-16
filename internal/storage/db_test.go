package storage

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// setupdTestDB creates and connects to a temporary uninitialized db
// Returns the connection and path
func setupTestDB(ctx context.Context,t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	// temporary db file
	dbPath := filepath.Join(t.TempDir(), "test.db")
	
	conn, err := OpenDB(ctx, dbPath)
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

func setupInitializedTestDB(ctx context.Context, t *testing.T) (*sql.DB, string, []byte) {
	t.Helper()
	
	conn, path := setupTestDB(ctx,t)
	masterPassword := []byte("correct-horse-battery-staple")
	if err := InitializeDB(ctx,conn,masterPassword); err != nil {
		t.Fatalf("InitializeDB failed: %v", err)
	}
	return conn, path, masterPassword
}

func TestInitializeDB(t *testing.T) {
	t.Run("Success_First_Initialization", func (t *testing.T){
		ctx := context.Background()
		conn, _ := setupTestDB(ctx,t)

		masterPassword := []byte("correct-horse-battery-staple")
		if err := InitializeDB(ctx,conn,masterPassword); err != nil {
			t.Fatalf("InitializeDB failed: %v", err)
		}

		// Check tables
		_, err := conn.Exec("INSERT INTO users (email, Server_Hash, Server_Salt) VALUES ('test_user',1,1)")
    	if err != nil {
     	   t.Errorf("Could not insert into 'users' after initialization: %v", err)
    	}

    	_, err = conn.Exec("INSERT INTO vault (service_name) VALUES ('facebook')")
    	if err != nil {
     	   t.Errorf("Could not insert into 'vault' after initialization: %v", err)
    	}
	})

	t.Run("Failure_Second_Initialization", func(t * testing.T){
		ctx := context.Background()
		conn, _, masterPassword := setupInitializedTestDB(ctx,t)

		if err := InitializeDB(ctx,conn,masterPassword); !errors.Is(err,ErrDBAlreadyInitialized) {
			t.Errorf("Expected %v, got: %v", ErrDBAlreadyInitialized,err)
		}
	})

	t.Run("Failure_Context_Cancelled", func(t *testing.T){
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Setup with base context
		conn, _ := setupTestDB(context.Background(), t) 
   		masterPassword := []byte("correct-horse-battery-staple")
		
		// Initialization with cancelled context
		err := InitializeDB(ctx, conn, masterPassword)

    	if err == nil {
        	t.Error("Expected InitializeDB to fail with a cancelled context, got nil")
    	} else if !errors.Is(err, context.Canceled) {
       		t.Errorf("Expected context.Canceled error, got: %v", err)
   		}
	})
}

func TestOpenDB(t *testing.T) {
	t.Run("Success_After_Initialization", func(t *testing.T) {
		ctx := context.Background()
		_, path, _ := setupInitializedTestDB(ctx,t)

		conn, err := OpenDB(ctx,path)
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
		_, path, _ := setupInitializedTestDB(context.Background(), t) 

		// Initialization with cancelled context
		conn, err := OpenDB(ctx,path)

		if conn != nil { t.Cleanup(func() { conn.Close() }) }
		if err == nil {
        	t.Error("Expected OpenDB to fail with a cancelled context, got nil")
    	} else if !errors.Is(err, context.Canceled) {
       		t.Errorf("Expected context.Canceled error, got: %v", err)
   		}
	})
}