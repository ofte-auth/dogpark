package model

import (
	"bytes"
	"context"
	"encoding/gob"
	"time"

	"github.com/google/uuid"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

// Constants for KV
const (
	SessionTTL = 40

	CollectionSessions = "sessions"
)

// Session represents a CA session.
type Session struct {
	ID                string
	PrincipalID       string
	PrincipalUsername string
	FIDOKeyID         string
	AAGUID            string
	State             string
	IPAddr            string
	UserAgent         string
	AgentSalt         string // TBD: See https://github.com/ofte-auth/dogpark/issues/2
	Nonce             uint32
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewSession creates a CA session.
func NewSession(principalID, fidoKeyID, aaguid, ipaddr, userAgent string) (*Session, error) {
	var err error
	switch {
	case len(principalID) < 8:
		err = multierr.Append(err, errors.New("invalid principal ID"))
	case len(fidoKeyID) < 8:
		err = multierr.Append(err, errors.New("invalid fidoKeyID"))
	case len(aaguid) < 8:
		err = multierr.Append(err, errors.New("invalid aaguid"))
	case ipaddr == "":
		err = multierr.Append(err, errors.New("invalid idaddr"))
	case userAgent == "":
		err = multierr.Append(err, errors.New("invalid userAgent"))
	}
	if err != nil {
		return nil, err
	}
	return &Session{
		ID:          uuid.New().String(),
		PrincipalID: principalID,
		FIDOKeyID:   fidoKeyID,
		AAGUID:      aaguid,
		State:       StateActive,
		IPAddr:      ipaddr,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}, nil
}

// Encode gobs a Session to serialized []byte.
func (s *Session) Encode() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(s)
	return buf.Bytes(), err
}

// Decode gobs a serialized []byte to a Session.
func (s *Session) Decode(b []byte) error {
	buf := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buf)
	return decoder.Decode(s)
}

// Put or Update a Session in the kv store.
func (s *Session) Put(ctx context.Context, manager store.Manager, ttlSeconds int64) error {
	if ttlSeconds == 0 {
		ttlSeconds = SessionTTL
	}
	b, err := s.Encode()
	if err != nil {
		return err
	}
	if err = manager.Put(ctx, CollectionSessions, s.ID, b, ttlSeconds); err != nil {
		return err
	}
	return nil
}

// Delete removes the `Session`.
func (s *Session) Delete(ctx context.Context, manager store.Manager, sessionID string) error {
	return manager.Delete(ctx, CollectionSessions, sessionID)
}

// SessionByID gets a Session by its ID.
func SessionByID(ctx context.Context, manager store.Manager, id string) (*Session, error) {
	b, err := manager.Get(ctx, CollectionSessions, id)
	if err != nil {
		return nil, err
	}
	session := new(Session)
	if err = session.Decode(b); err != nil {
		return nil, errors.Wrap(err, "decoding session from store")
	}
	return session, nil
}

// Sessions returns sessions from the store.
func Sessions(ctx context.Context, manager store.Manager, params *util.APIParams) ([]*Session, int64, error) {
	newestFirst := params.OrderDirection == "DESC"
	results, total, err := manager.List(ctx, CollectionSessions, params.Limit, params.Page, newestFirst)
	if err != nil {
		return nil, 0, err
	}
	result := []*Session{}
	for _, v := range results {
		session := new(Session)
		if err = session.Decode(v.Value); err != nil {
			return nil, 0, errors.Wrap(err, "decoding session from list")
		}
		result = append(result, session)
	}
	return result, total, nil
}
