// Copyright (c) 2020 Ofte LLC,
// subject to the terms and conditions defined in the file LICENSE

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/ofte-auth/dogpark/internal"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/util"
	log "github.com/sirupsen/logrus"
)

// Migrates the dogpark database tables and indexes.
func main() {
	var (
		err    error
		dbConn db.DB
	)

	fmt.Println(internal.VersionVerbose())

	util.InitConfig()

	err = util.Retry(10, 250*time.Millisecond, func() error {
		dbConn, err = db.GetConnection(util.AllConfigSettings())
		if err != nil {
			log.WithError(err).WithField("service", "auth").Warning("Error connecting to db, retrying")
		}
		return err
	})
	if err != nil {
		log.WithError(err).WithField("service", "auth").Warning("Unable to connect to db, exiting")
		os.Exit(1)
	}

	err = model.Migrate(dbConn)
	if err != nil {
		panic(err)
	}

	fmt.Println("Migrate succeeded")
}
