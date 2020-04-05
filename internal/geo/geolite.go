package geo

import (
	"net"
	"strings"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang"
	"github.com/pkg/errors"
)

// An implementation of the GeoResolver for the MaxMind GeoLite IP DB
// See https://dev.maxmind.com/geoip/geoip2/geolite2/

// MaxMindGeoLiteConfig ...
type MaxMindGeoLiteConfig struct {
	DBLocation string
}

type geoLiteImpl struct {
	db *geoip2.Reader
}

func (impl *geoLiteImpl) Init(options interface{}) error {
	var (
		ok     bool
		err    error
		config *MaxMindGeoLiteConfig
	)
	config, ok = options.(*MaxMindGeoLiteConfig)
	if !ok {
		return errors.New("expecting Init options to be *GeoLiteConfig")
	}

	impl.db, err = geoip2.Open(config.DBLocation)
	if err != nil {
		return errors.Wrapf(err, "unable to open filename %s", config.DBLocation)
	}
	return nil
}

func (impl *geoLiteImpl) Close() {
	if impl.db != nil {
		_ = impl.db.Close()
	}
}

func (impl *geoLiteImpl) Resolve(ipAddress string) (*GeoEntry, error) {
	if ipAddress == "127.0.0.1" || strings.HasPrefix(ipAddress, "[::1]") {
		ipAddress = "70.20.56.240"
	}
	ip := net.ParseIP(ipAddress)
	record, err := impl.db.City(ip)
	if err != nil {
		return nil, err
	}

	entry := &GeoEntry{
		IPAddress: ipAddress,
		Timestamp: time.Now(),
	}
	if country, ok := record.Country.Names["en"]; ok {
		entry.Country = country
	}
	if len(record.Subdivisions) > 0 {
		if region, ok := record.Subdivisions[0].Names["en"]; ok {
			entry.Region = region
		}
	}
	if city, ok := record.City.Names["en"]; ok {
		entry.City = city
	}
	entry.Latitude = record.Location.Latitude
	entry.Longitude = record.Location.Longitude

	return entry, nil
}
