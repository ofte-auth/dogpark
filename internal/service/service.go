package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/micro/go-micro/v2/broker"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/geo"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/store"
	log "github.com/sirupsen/logrus"
)

// Service represents a base structure for services.
type Service struct {
	name   string
	db     db.DB
	kv     store.Manager
	broker broker.Broker
	geo    geo.Resolver
	params map[string]string
}

// Stop closes all open handles.
func (s Service) Stop() {
	if s.db != nil {
		_ = db.CloseConnection(s.db)
	}
	if s.kv != nil {
		_ = s.kv.Close()
	}
	if s.geo != nil {
		s.geo.Close()
	}
}

// Audit sends auditing data to configured endpoints.
func (s Service) Audit(ctx context.Context, group, action string, p *model.Principal, key *model.FIDOKey, auditError error) {
	entry := &model.AuditEntry{
		Group:     group,
		Action:    action,
		CreatedAt: time.Now(),
	}
	ipAddr, ok := ctx.Value(ContextIPAddr).(string)
	if ok {
		entry.IPAddr = ipAddr
	}
	userAgent, ok := ctx.Value(ContextUserAgent).(string)
	if ok {
		entry.UserAgent = userAgent
	}
	if p != nil {
		entry.PrincipalID = p.ID
		entry.PrincipalUsername = p.Username
	}
	if key != nil {
		entry.FidoKeyID = key.ID
		entry.FidoAAGUID = key.AAGUID
	}
	if entry.IPAddr != "" && s.geo != nil {
		geoEntry, err := s.geo.Resolve(entry.IPAddr)
		if err == nil {
			entry.Latitude = geoEntry.Latitude
			entry.Longitude = geoEntry.Longitude
			entry.Country = geoEntry.Country
			entry.Region = geoEntry.Region
			entry.City = geoEntry.City
		} else {
			log.WithError(err).WithField("ip_addr", entry.IPAddr).Error("Resolving geo ip")
		}
	}
	if auditError != nil {
		entry.Anomaly = auditError.Error()
	}
	err := s.db.Create(entry).Error
	if err != nil {
		log.WithError(err).Error("Inserting audit entry")
	}

	// If a message broker is configured, send the auditevent.
	if s.broker != nil {
		topic := fmt.Sprintf("dogpark.%s.%s", group, action)
		body, _ := json.Marshal(entry)
		message := &broker.Message{Body: body}
		err = s.broker.Publish(topic, message)
		if err != nil {
			log.WithError(err).Error("Sending audit entry through message broker")
		}
	}
}
