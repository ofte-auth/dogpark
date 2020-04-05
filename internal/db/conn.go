package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"

	// implicitly load postgres driver
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// DB aliases the ORM package.
type DB = *gorm.DB

var paramKeys map[string]string = map[string]string{
	"db_host":     "host",
	"db_port":     "port",
	"db_name":     "dbname",
	"db_user":     "user",
	"db_password": "password",
	"db_sslmode":  "sslmode",
}

// GetConnection opens the DB via gorm. The returned handle is safe for concurrent and reuse.
func GetConnection(params map[string]interface{}) (DB, error) {
	var (
		err              error
		connectionParams strings.Builder
	)

	for k, v := range params {
		if _, ok := paramKeys[k]; !ok {
			continue
		}
		value, ok := v.(string)
		if !ok {
			return nil, errors.Errorf("converting parameter %s", k)
		}
		_, err = connectionParams.WriteString(fmt.Sprintf("%s=%s ", paramKeys[k], value))
		if err != nil {
			return nil, err
		}
	}
	return gorm.Open("postgres", connectionParams.String())
}

// CloseConnection closes the db connection. If it's a test DB, it also DELETEs the DB.
func CloseConnection(db DB) error {
	_, ok := db.Get("testDB")
	if ok {
		// Allow auditing to complete in test DBs
		time.Sleep(50 * time.Millisecond)
		_ = DestroyTestDB(db)
	}
	return db.Close()
}
