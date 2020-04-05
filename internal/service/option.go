package service

import (
	"github.com/micro/go-micro/v2/broker"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/geo"
	"github.com/ofte-auth/dogpark/internal/store"
)

// OptionDB set a DB connection option.
func OptionDB(db db.DB) func(*Service) error {
	return func(svc *Service) error {
		svc.db = db
		return nil
	}
}

// OptionKV set a KV manager option.
func OptionKV(kv store.Manager) func(*Service) error {
	return func(svc *Service) error {
		svc.kv = kv
		return nil
	}
}

// OptionRP sets relying party configation options.
func OptionRP(rpDisplayName, rpID, rpOrigin string) func(*Service) error {
	return func(svc *Service) error {
		if svc.params == nil {
			svc.params = make(map[string]string)
		}
		svc.params["rpDisplayName"] = rpDisplayName
		svc.params["rpID"] = rpID
		svc.params["rpOrigin"] = rpOrigin
		return nil
	}
}

// OptionGeoResolver sets a geo resolver.
func OptionGeoResolver(geo geo.Resolver) func(*Service) error {
	return func(svc *Service) error {
		svc.geo = geo
		return nil
	}
}

// OptionParams sets a key,value option. Multiple can be set.
func OptionParams(params map[string]string) func(*Service) error {
	return func(svc *Service) error {
		svc.params = params
		return nil
	}
}

// OptionMessageBroker sets a broker client option.
func OptionMessageBroker(broker broker.Broker) func(*Service) error {
	return func(svc *Service) error {
		svc.broker = broker
		return nil
	}
}
