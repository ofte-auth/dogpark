// Copyright (c) 2020 Ofte LLC,
// subject to the terms and conditions defined in the file LICENSE

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fraugster/cli"
	"github.com/ofte-auth/dogpark/api/http"
	"github.com/ofte-auth/dogpark/internal"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/geo"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/ofte-auth/dogpark/internal/util"
	log "github.com/sirupsen/logrus"
	config "github.com/spf13/viper"
)

func main() {
	var (
		err    error
		dbConn db.DB
	)
	fmt.Println(internal.VersionVerbose())

	util.InitConfig()
	ctx := cli.Context()

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

	var kv store.Manager
	cfg := store.EtcdConfig{
		Endpoints: config.GetStringSlice("kv_endpoints"),
	}
	err = util.Retry(10, 250*time.Millisecond, func() error {
		kv, err = store.NewManager(ctx, cfg)
		if err != nil {
			log.WithError(err).WithField("service", "auth").Warning("Error connecting to kv store, retrying")
		}
		return err
	})
	if err != nil {
		log.WithError(err).WithField("service", "auth").Warning("Unable to connect to kv store, exiting")
		os.Exit(1)
	}

	geoConfig := &geo.IPStackConfig{APIKey: config.GetString("ipstack_access_key")}
	geoResolver, err := geo.NewGeoResolver(geoConfig)
	if err != nil {
		panic(err)
	}

	httpService, err := http.NewAuthHandler(ctx,
		http.OptionDB(dbConn),
		http.OptionKV(kv),
		http.OptionHTTPPort(config.GetInt("http_port")),
		http.OptionTLS(config.GetString("tls_certificate_file"), config.GetString("tls_private_key_file")),
		http.OptionGeoResolver(geoResolver),
		http.OptionParams("rpDisplayName", config.GetString("rp_display_name")),
		http.OptionParams("rpID", config.GetString("rp_id")),
		http.OptionParams("rpOrigin", config.GetString("rp_origin")),
	)
	if err != nil {
		panic(err)
	}
	httpService.Init()
	go func() {
		err = httpService.Start()
		if err != nil {
			panic(err)
		}
	}()

	<-ctx.Done()
	_ = httpService.Stop()
}
