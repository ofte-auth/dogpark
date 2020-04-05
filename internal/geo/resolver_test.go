package geo

import (
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func Test_GeoLiteImpl(t *testing.T) {
	geoResolver, err := NewGeoResolver(&MaxMindGeoLiteConfig{"../../deploy/GeoLite2-City.mmdb"})
	if strings.Contains(err.Error(), "no such file") {
		t.Skip(err.Error())
		return
	}
	require.NoError(t, err)
	entry, err := geoResolver.Resolve("70.20.56.211")
	require.NoError(t, err)
	require.Equal(t, "United States", entry.Country)
}

func Test_IPStackImpl(t *testing.T) {
	resolver, err := NewGeoResolver(&IPStackConfig{
		APIKey: os.Getenv("IPSTACK_ACCESS_KEY"),
	})
	if strings.Contains(err.Error(), "no api key supplied") {
		t.Skip(err.Error())
		return
	}
	require.NoError(t, err)
	entry, err := resolver.Resolve("70.20.56.211")
	require.NoError(t, err)
	require.Equal(t, "United States", entry.Country)
	spew.Dump(entry)
}
