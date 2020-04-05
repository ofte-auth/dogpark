package service

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
)

// Consts for auth services
const (
	CollectionPendingFIDORegistration = "fidoPendingReg"
	CollectionPendingFIDOLogin        = "fidoPendingLogin"
)

// Error constants
var (
	ErrPrincipalRevoked = errors.New("principal rekoked")
)

// Auth defines the auth service interface.
type Auth interface {
	GetOrCreatePrincipal(context.Context, map[string]string) (*model.Principal, *APIError)
	StartFIDORegistration(context.Context, string) (*protocol.CredentialCreation, *APIError)
	FinishFIDORegistration(context.Context, string, *http.Request) (*model.FIDOKey, *APIError)
	StartFIDOLogin(context.Context, string) (*protocol.CredentialAssertion, *APIError)
	FinishFIDOLogin(context.Context, string, *http.Request) (*model.Principal, *APIError)

	Stop()
}

type authService struct {
	Service
	webAuthn *webauthn.WebAuthn
}

// NewAuthService creates a new instance.
func NewAuthService(ctx context.Context, options ...func(*Service) error) (Auth, error) {
	var err error
	service := &authService{
		Service: Service{
			name: "dogpark-auth-service",
		},
	}
	for _, option := range options {
		err := option(&(service).Service)
		if err != nil {
			return nil, err
		}
	}
	var required = []string{"rpDisplayName", "rpID", "rpOrigin"}
	for _, v := range required {
		if _, ok := service.params[v]; !ok {
			return nil, errors.Errorf("required parameter %s missing", v)
		}
	}
	service.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:         service.params["rpDisplayName"],
		RPID:                  service.params["rpID"],
		RPOrigin:              service.params["rpOrigin"],
		RPIcon:                service.params["rpIcon"],
		AttestationPreference: protocol.PreferDirectAttestation,
	})
	if err != nil {
		return nil, errors.Wrap(err, "initializing protocol options")
	}
	return service, nil
}

func (s *authService) Stop() {
	s.Service.Stop()
}

func (s *authService) GetOrCreatePrincipal(ctx context.Context, params map[string]string) (*model.Principal, *APIError) {
	var (
		p   *model.Principal
		err error
	)
	detail := "getting or creating principal"
	// Auditing
	defer func() {
		go s.Audit(ctx, "auth", "getOrCreatePrincipal", p, nil, err)
	}()

	id := params["id"]
	if id == "" {
		id = params["username"]
	}
	p, err = model.PrincipalByID(ctx, s.db, id, true)

	switch err {
	case nil:
		return p, nil
	case model.ErrRecordNotFound:
		// do nothing
	default:
		err = errors.Wrap(err, "getting principal by username")
		return nil, NewAPIError(500, err, detail)
	}
	p = model.NewPrincipal(params["id"], params["username"], model.StateActive, params["displayName"], params["icon"])
	err = p.Insert(ctx, s.db)
	if err != nil {
		err = errors.Wrap(err, "inserting new principal record")
		return nil, NewAPIError(400, err, detail)
	}
	return p, nil
}

func (s *authService) StartFIDORegistration(ctx context.Context, username string) (*protocol.CredentialCreation, *APIError) {
	var (
		p   *model.Principal
		err error
	)
	detail := "starting FIDO registration"
	// Auditing
	defer func() {
		go s.Audit(ctx, "auth", "startFIDORegistration", p, nil, err)
	}()

	p, err = model.PrincipalByUsername(ctx, s.db, username, true)
	if err != nil {
		err = errors.Wrap(err, "locating principal by username")
		return nil, NewAPIError(404, err, detail)
	}

	if p.State != model.StateActive {
		err = errors.Errorf("principal state (%s) not active", p.State)
		return nil, NewAPIError(401, err, detail)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = p.CredentialList()
	}
	options, sessionData, err := s.webAuthn.BeginRegistration(p, registerOptions)
	if err != nil {
		err = errors.Wrap(err, "beginning registration")
		return nil, NewAPIError(400, err, detail)
	}

	marshaledData, err := json.Marshal(sessionData)
	if err != nil {
		err = errors.Wrap(err, "marshaling reg session data")
		return nil, NewAPIError(400, err, detail)
	}

	// store the reg session data in the keystore with TTL
	err = s.kv.Put(ctx, CollectionPendingFIDORegistration, username, marshaledData, 30)
	if err != nil {
		err = errors.Wrap(err, "storing reg session data")
		return nil, NewAPIError(400, err, detail)
	}

	return options, nil
}

func (s *authService) FinishFIDORegistration(ctx context.Context, username string, r *http.Request) (*model.FIDOKey, *APIError) {
	var (
		p       *model.Principal
		err     error
		fidoKey *model.FIDOKey
	)
	detail := "finishing FIDO registration"
	// Auditing
	defer func() {
		go s.Audit(ctx, "auth", "finishFIDORegistration", p, fidoKey, err)
	}()

	p, err = model.PrincipalByUsername(ctx, s.db, username, true)
	if err != nil {
		err = errors.Wrap(err, "locating principal by username")
		return nil, NewAPIError(404, err, detail)
	}
	sessionData := webauthn.SessionData{}
	d, err := s.kv.Get(ctx, CollectionPendingFIDORegistration, username)
	if err != nil {
		err = errors.Wrap(err, "getting stored session data from keystore")
		return nil, NewAPIError(400, err, detail)
	}
	_ = s.kv.Delete(ctx, CollectionPendingFIDORegistration, username)

	err = json.Unmarshal(d, &sessionData)
	if err != nil {
		err = errors.Wrap(err, "unmarshaling session data")
		return nil, NewAPIError(400, err, detail)
	}

	creationData, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		err = errors.Wrapf(err, "parsing credential creation response '%s', '%s'",
			err.(*protocol.Error).Details,
			err.(*protocol.Error).DevInfo,
		)
		return nil, NewAPIError(400, err, detail)
	}

	credential, err := s.webAuthn.CreateCredential(p, sessionData, creationData)
	if err != nil {
		err = errors.Wrapf(err, "verifying the registration '%s', '%s'",
			err.(*protocol.Error).Details,
			err.(*protocol.Error).DevInfo,
		)
		return nil, NewAPIError(400, err, detail)
	}

	aaguid, err := uuid.FromBytes(credential.Authenticator.AAGUID)
	if err != nil {
		err = errors.Wrapf(err, "parsing aaguid '%v'", credential.Authenticator.AAGUID)
		return nil, NewAPIError(400, err, detail)
	}

	now := time.Now()
	fidoKey = &model.FIDOKey{
		ID:                hex.EncodeToString(credential.ID),
		AAGUID:            aaguid.String(),
		State:             model.StateActive,
		PrincipalID:       p.ID,
		PrincipalUsername: p.Username,
		PublicKey:         credential.PublicKey,
		AttestationType:   credential.AttestationType,
		Nonce:             credential.Authenticator.SignCount,
		LastUsed:          now,
		CreatedAt:         now,
		ModifiedAt:        now,
	}

	x5c, found := creationData.Response.AttestationObject.AttStatement["x5c"].([]interface{})
	if !found || len(x5c) == 0 {
		err = errors.New("No certificate information found or made available")
		return nil, NewAPIError(400, err, detail)
	}
	c := x5c[0]
	cb, cv := c.([]byte)
	if !cv {
		err = errors.New("error getting certificate from x5c cert chain")
		return nil, NewAPIError(400, err, detail)
	}
	ct, err := x509.ParseCertificate(cb)
	if err != nil {
		err = errors.Wrap(err, "error parsing certificate from ASN.1 data")
		return nil, NewAPIError(400, err, detail)
	}
	fidoKey.CertCommonName = ct.Issuer.CommonName
	if len(ct.Issuer.Organization) > 0 {
		fidoKey.CertOrganization = ct.Issuer.Organization[0]
	}
	fidoKey.CertSerial = ct.SerialNumber.Int64()
	if ct.NotBefore.After(time.Now()) || ct.NotAfter.Before(time.Now()) {
		err = errors.Errorf("cert in chain outside of time bounds, notAfter: %s", ct.NotAfter)
		return nil, NewAPIError(400, err, detail)
	}
	fidoKey.NotValidBefore = ct.NotBefore
	fidoKey.NotValidAfter = ct.NotAfter

	// Check against AAGUID whitelist
	whitelist, err := model.WhitelistAAGUIDs(ctx, s.db)
	if err != nil {
		err = errors.Wrap(err, "error getting aaguid whitelist")
		return nil, NewAPIError(500, err, detail)
	}
	if len(whitelist) > 0 {
		if !whitelist.Has(aaguid.String()) {
			err = errors.Errorf("authenticator guid %s, %s is not in the whitelist %v",
				aaguid.String(),
				fidoKey.CertCommonName,
				whitelist.Values(),
			)
			return nil, NewAPIError(401, err, detail)
		}
	}

	// Check for revoked AAGUIDs
	guid, err := model.AAGUIDByID(ctx, s.db, aaguid.String())
	switch err {
	case nil:
		if guid.State == model.StateRevoked {
			err = errors.Errorf("authenticator guid %s, %s is blacklisted", guid.ID, guid.Label)
			return nil, NewAPIError(401, err, detail)
		}
	case model.ErrRecordNotFound:
		guid := &model.AAGUID{
			ID:    aaguid.String(),
			Label: fmt.Sprintf("%s %s", fidoKey.CertOrganization, fidoKey.CertCommonName),
		}
		err := s.db.Create(guid).Error
		if err != nil {
			err = errors.Wrapf(err, "inserting new aaguid, guid %s, %s", guid.ID, guid.Label)
			return nil, NewAPIError(500, err, detail)
		}
	}

	err = s.db.Save(fidoKey).Error
	if err != nil {
		err = errors.Wrap(err, "saving fidokey record")
		return nil, NewAPIError(500, err, detail)
	}

	return fidoKey, nil
}

func (s *authService) StartFIDOLogin(ctx context.Context, username string) (*protocol.CredentialAssertion, *APIError) {
	var (
		p   *model.Principal
		err error
	)
	detail := "starting FIDO login"
	// Auditing
	defer func() {
		go s.Audit(ctx, "auth", "startFIDOLogin", p, nil, err)
	}()

	p, err = model.PrincipalByUsername(ctx, s.db, username, true)
	if err != nil {
		err = errors.Wrap(err, "locating principal by username")
		return nil, NewAPIError(400, err, detail)
	}

	if p.State != model.StateActive {
		err = errors.Errorf("principal state (%s) not active", p.State)
		return nil, NewAPIError(401, err, detail)
	}

	assert, sessionData, err := s.webAuthn.BeginLogin(p)
	if err != nil {
		err = errors.Wrap(err, "getting credential request options")
		return nil, NewAPIError(400, err, detail)
	}
	marshaledData, err := json.Marshal(sessionData)
	if err != nil {
		err = errors.Wrap(err, "marshaling login session data")
		return nil, NewAPIError(400, err, detail)
	}
	// store the login session data in the keystore with TTL
	err = s.kv.Put(ctx, CollectionPendingFIDOLogin, username, marshaledData, 30)
	if err != nil {
		err = errors.Wrap(err, "storing reg session data")
		return nil, NewAPIError(400, err, detail)
	}

	return assert, nil
}

func (s *authService) FinishFIDOLogin(ctx context.Context, username string, r *http.Request) (*model.Principal, *APIError) {
	var (
		p       *model.Principal
		err     error
		fidoKey *model.FIDOKey
	)
	detail := "finishing FIDO login"
	// Auditing
	defer func() {
		go s.Audit(ctx, "auth", "finishFIDOLogin", p, fidoKey, err)
	}()

	p, err = model.PrincipalByUsername(ctx, s.db, username, true)
	if err != nil {
		err = errors.Wrap(err, "locating principal by username")
		return nil, NewAPIError(400, err, detail)
	}
	sessionData := webauthn.SessionData{}
	d, err := s.kv.Get(ctx, CollectionPendingFIDOLogin, username)
	if err != nil {
		err = errors.Wrap(err, "getting stored session data from keystore")
		return nil, NewAPIError(400, err, detail)
	}
	_ = s.kv.Delete(ctx, CollectionPendingFIDOLogin, username)
	err = json.Unmarshal(d, &sessionData)
	if err != nil {
		err = errors.Wrap(err, "unmarshaling session data")
		return nil, NewAPIError(400, err, detail)
	}

	cred, err := s.webAuthn.FinishLogin(p, sessionData, r)
	if err != nil {
		err = errors.Wrap(err, "validating fido login")
		return nil, NewAPIError(400, err, detail)
	}
	if cred.Authenticator.CloneWarning {
		err = errors.Wrap(err, "cloned authenticator detected")
		return nil, NewAPIError(400, err, detail)
	}

	fidoKey, err = model.FIDOKeyByID(ctx, s.db, hex.EncodeToString(cred.ID))
	if err != nil {
		err = errors.Wrap(err, "getting fido key by id")
		return nil, NewAPIError(500, err, detail)
	}

	// Check the key's revocation status
	if fidoKey.State == model.StateRevoked {
		err = errors.Errorf("key %v, aaaguid %s is revoked", fidoKey.ID, fidoKey.AAGUID)
		return nil, NewAPIError(401, err, detail)
	}

	// Check key's valid time interval
	now := time.Now()
	if now.Before(fidoKey.NotValidBefore) || now.After(fidoKey.NotValidAfter) {
		err = errors.Errorf("time not within valid range, %s - %s", fidoKey.NotValidBefore, fidoKey.NotValidAfter)
		return nil, NewAPIError(401, err, detail)
	}

	// Check against AAGUID whitelist
	whitelist, err := model.WhitelistAAGUIDs(ctx, s.db)
	if err != nil {
		err = errors.Wrap(err, "error getting aaguid whitelist")
		return nil, NewAPIError(500, err, detail)
	}
	if len(whitelist) > 0 {
		if !whitelist.Has(fidoKey.AAGUID) {
			err = errors.Errorf("authenticator guid %s, %s is not in the whitelist %v",
				fidoKey.AAGUID,
				fidoKey.CertCommonName,
				whitelist.Values(),
			)
			return nil, NewAPIError(401, err, detail)
		}
	}

	// check against blacklisted authenticators
	guid, err := model.AAGUIDByID(ctx, s.db, fidoKey.AAGUID)
	if guid != nil {
		if guid.State == model.StateRevoked {
			err = errors.Errorf("authenticator, guid %s, %s is blacklisted", guid.ID, guid.Label)
			return nil, NewAPIError(401, err, detail)
		}
	}

	fidoKey.Nonce = cred.Authenticator.SignCount
	fidoKey.LastUsed = time.Now()
	err = s.db.Save(fidoKey).Error
	if err != nil {
		err = errors.Wrap(err, "saving fido key")
		return nil, NewAPIError(500, err, detail)
	}

	session, _ := model.NewSession(p.ID, fidoKey.ID, fidoKey.AAGUID, util.ClientIP(r), r.UserAgent())
	if session != nil {
		_ = session.Put(ctx, s.kv, model.SessionTTL)
	}

	return p, nil
}
