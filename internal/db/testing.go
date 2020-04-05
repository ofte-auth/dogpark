package db

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
)

// GetTestDB creates a test db.
func GetTestDB() (*gorm.DB, error) {

	dbName := util.RandomAlphaString(16)

	db, err := gorm.Open("postgres", "host=localhost port=5432 user=postgres sslmode=require")
	if err != nil {
		return nil, err
	}

	err = db.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE template0 ENCODING 'UTF8'", dbName)).Error
	if err != nil {
		return nil, err
	}

	connString := fmt.Sprintf("host=localhost port=5432 dbname=%s user=postgres sslmode=require", dbName)
	db, err = gorm.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	db = db.Set("databaseName", dbName).Set("testDB", true)

	return db, err
}

// DestroyTestDB destroys a test database.
func DestroyTestDB(db *gorm.DB) error {

	dbName, ok := db.Get("databaseName")
	if !ok {
		return errors.New("No databaseName in context")
	}
	dbName, ok = dbName.(string)
	if !ok {
		return errors.New("Invalid type for databaseName")
	}
	err := db.Close()
	if err != nil {
		return err
	}
	db, err = gorm.Open("postgres", "host=localhost port=5432 user=postgres sslmode=require")
	if err != nil {
		return err
	}
	defer db.Close()
	err = db.Exec(fmt.Sprintf("DROP DATABASE %s", dbName)).Error
	if err != nil {
		return err
	}
	return nil
}
