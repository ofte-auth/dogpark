package db

import (
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	config "github.com/spf13/viper"

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
func GetConnection() (DB, error) {
	var connectionParams strings.Builder

	for k, v := range paramKeys {
		value := config.GetString(k)

		if len(value) > 0 {
			_, _ = connectionParams.WriteString(fmt.Sprintf("%s=%s ", v, value))
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
