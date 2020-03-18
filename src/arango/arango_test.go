package arango

import (
	"context"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"testing"
	"time"
)

const (
	syslogURL = "localhost:2514"
	username  = "root"
	passwd    = "root"
	host      = "localhost"
	port      = "8529"
)

func TestArango_Initialize(t *testing.T) {
	t.Run("Invalid credential", func(t *testing.T) {
		connectionDetails := map[string]interface{}{
			"syslog_url": syslogURL,
			"username":   "non-existedUser",
			"password":   "non-existedUserPass",
			"host":       host,
			"port":       port,
		}
		db := new(10, 10, 32)

		_, err := db.Init(context.Background(), connectionDetails, true)
		if err == nil {
			t.Fatalf("err: %s", "When providing non existed credential, the verification should fail.")
		}
	})
	t.Run("Optional syslog url (local)", func(t *testing.T) {

		connectionDetails := map[string]interface{}{
			"username": username,
			"password": passwd,
			"host":     host,
			"port":     port,
		}
		db := new(10, 10, 32)

		_, err := db.Init(context.Background(), connectionDetails, true)
		if err != nil {
			t.Fatalf("err: %s", err)
		}
	})
	t.Run("Valid credential", func(t *testing.T) {
		setupPlugin(true, t)
	})
}

func TestArango_CreateUser(t *testing.T) {

	t.Run("Create DB, credential and assign DB access to credential", func(t *testing.T) {
		const databaseName = "CreateUserCokedb"
		db, usernameConfig := setupPlugin(false, t)

		statements := dbplugin.Statements{
			Creation:   []string{databaseName},
			Revocation: []string{},
		}
		username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		if username == "" {
			t.Fatalf("expected empty username, got [%s]", username)
		}
		if password == "" {
			t.Fatalf("expected empty password, got [%s]", password)
		}
		db.deleteUser(username)
		db.deleteDatabase(databaseName)
	})

	t.Run("Create credential only", func(t *testing.T) {
		db, usernameConfig := setupPlugin(false, t)
		username, password, err := db.CreateUser(context.Background(), dbplugin.Statements{}, usernameConfig, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		if username == "" {
			t.Fatalf("expected empty username, got [%s]", username)
		}
		if password == "" {
			t.Fatalf("expected empty password, got [%s]", password)
		}
		db.deleteUser(username)
	})
}

func TestArango_RevokeUser(t *testing.T) {
	t.Run("Revoke user and delete database", func(t *testing.T) {
		db, usernameConfig := setupPlugin(false, t)
		const databaseName = "pessidb"
		statements := dbplugin.Statements{
			Creation:   []string{databaseName},
			Revocation: []string{},
		}
		username, password, err := db.CreateUser(context.Background(), statements, usernameConfig, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		if username == "" {
			t.Fatalf("expected empty username, got [%s]", username)
		}
		if password == "" {
			t.Fatalf("expected empty password, got [%s]", password)
		}
		err = db.RevokeUser(context.Background(), statements, username)
		if err != nil {
			t.Fatalf("err: %s", err)
		}
	})

	t.Run("Revoke user only", func(t *testing.T) {
		db, usernameConfig := setupPlugin(false, t)

		username, password, err := db.CreateUser(context.Background(), dbplugin.Statements{}, usernameConfig, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		if username == "" {
			t.Fatalf("expected empty username, got [%s]", username)
		}
		if password == "" {
			t.Fatalf("expected empty password, got [%s]", password)
		}
		err = db.RevokeUser(context.Background(), dbplugin.Statements{}, username)
		if err != nil {
			t.Fatalf("err: %s", err)
		}
	})
}

func setupPlugin(verifyConnection bool, t *testing.T) (*Arango, dbplugin.UsernameConfig) {
	// provide valid connection information below.
	connectionDetails := map[string]interface{}{
		"syslog_url": syslogURL,
		"username":   username,
		"password":   passwd,
		"host":       host,
		"port":       port,
	}
	db := new(10, 10, 32)

	_, err := db.Init(context.Background(), connectionDetails, verifyConnection)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	usernameConfig := dbplugin.UsernameConfig{
		DisplayName: "test-long-displayname",
		RoleName:    "test-long-rolename",
	}
	return db, usernameConfig
}
