package geo

import (
	"time"

	"github.com/pkg/errors"
)

// Resolver defines an IP-Geographic region resolver.
type Resolver interface {
	Init(options interface{}) error
	Close()
	Resolve(string) (*GeoEntry, error)
}

// NewGeoResolver creates a new GeoResolver.
// Note: this currently invokes the MaxMind Geo Resolver with the
// open-source GeoIP database
func NewGeoResolver(options interface{}) (Resolver, error) {
	var resolver Resolver
	switch options.(type) {
	case *MaxMindGeoLiteConfig:
		resolver = new(geoLiteImpl)
	case *IPStackConfig:
		resolver = new(ipStackImpl)
	default:
		return nil, errors.Errorf("Unknown geo resolver config type %T", options)
	}
	if err := resolver.Init(options); err != nil {
		return nil, err
	}
	return resolver, nil
}

// GeoEntry defines data derived from browser info and ip address.
type GeoEntry struct {
	IPAddress string    `json:"ipAddress"`
	UserAgent string    `json:"userAgent"`
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	City      string    `json:"city"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	Timestamp time.Time `json:"timestamp"`
}
