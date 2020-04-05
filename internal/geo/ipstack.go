package geo

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
)

// An implementation of the ipstack.api geo REST API
// See https://ipstack.com

// IPStackConfig ...
type IPStackConfig struct {
	APIKey string
}

type ipStackImpl struct {
	apiKey string
	cache  *lru.Cache
}

func (impl *ipStackImpl) Init(options interface{}) error {
	var (
		ok     bool
		err    error
		config *IPStackConfig
	)
	config, ok = options.(*IPStackConfig)
	if !ok {
		return errors.New("expecting Init options to be *IPStackConfig")
	}

	impl.apiKey = config.APIKey
	if len(impl.apiKey) == 0 {
		return errors.New("no api key supplied")
	}
	impl.cache, err = lru.New(1024)
	if err != nil {
		return errors.Wrapf(err, "unable to create lru cache")
	}
	return nil
}

func (impl *ipStackImpl) Close() {
}

func (impl *ipStackImpl) Resolve(ipAddress string) (*GeoEntry, error) {
	var (
		err   error
		entry *GeoEntry
	)
	if ipAddress == "127.0.0.1" || strings.HasPrefix(ipAddress, "[::1]") {
		ipAddress = "70.20.56.211"
	}
	val, ok := impl.cache.Get(ipAddress)
	if ok {
		return val.(*GeoEntry), nil
	}

	resp, err := http.Get(fmt.Sprintf("http://api.ipstack.com/%s?access_key=%s", ipAddress, impl.apiKey))
	if err != nil || resp.StatusCode != 200 {
		return nil, errors.Wrap(err, "getting geo ip entry")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response body")
	}
	defer resp.Body.Close()

	var values ipStackResponse
	err = json.Unmarshal(body, &values)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalling response body")
	}

	entry = &GeoEntry{
		IPAddress: values.IP,
		Country:   values.CountryName,
		Region:    values.RegionCode,
		City:      values.City,
		Latitude:  values.Latitude,
		Longitude: values.Longitude,
		Timestamp: time.Now(),
	}
	impl.cache.Add(ipAddress, entry)
	return entry, nil
}

type ipStackResponse struct {
	IP            string  `json:"ip"`
	Type          string  `json:"type"`
	ContinentCode string  `json:"continent_code"`
	ContinentName string  `json:"continent_name"`
	CountryCode   string  `json:"country_code"`
	CountryName   string  `json:"country_name"`
	RegionCode    string  `json:"region_code"`
	RegionName    string  `json:"region_name"`
	City          string  `json:"city"`
	Zip           string  `json:"zip"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Location      struct {
		GeonameID int    `json:"geoname_id"`
		Capital   string `json:"capital"`
		Languages []struct {
			Code   string `json:"code"`
			Name   string `json:"name"`
			Native string `json:"native"`
		} `json:"languages"`
		CountryFlag             string `json:"country_flag"`
		CountryFlagEmoji        string `json:"country_flag_emoji"`
		CountryFlagEmojiUnicode string `json:"country_flag_emoji_unicode"`
		CallingCode             string `json:"calling_code"`
		IsEu                    bool   `json:"is_eu"`
	} `json:"location"`
}
