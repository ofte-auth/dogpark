package model

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
)

// Principal identifies a person in the system. Only publicly available data is stored.
type Principal struct {
	ID          string     `json:"id"`
	Username    string     `gorm:"index" json:"username"`
	State       string     `gorm:"index" json:"state"`
	DisplayName string     `json:"displayName"`
	Icon        string     `json:"icon"`
	CreatedAt   time.Time  `gorm:"index" json:"createdAt"`
	FIDOKeys    []*FIDOKey `json:"fidoKeys,omitempty"`
}

// NewPrincipal creates a new Principal.
func NewPrincipal(id string, username string, state string, displayName string, icon string) *Principal {
	return &Principal{
		ID:          id,
		Username:    username,
		State:       state,
		DisplayName: displayName,
		Icon:        icon,
	}
}

// BeforeCreate performs pre-insert steps.
func (p *Principal) BeforeCreate(scope *gorm.Scope) error {
	if len(p.Username) == 0 && len(p.ID) == 0 {
		return errors.New("Username and ID cannot both be nil")
	}
	if len(p.ID) == 0 {
		// make a hash of the username
		h := fnv.New64()
		_, _ = h.Write([]byte(p.Username))
		id := make([]byte, 8)
		binary.LittleEndian.PutUint64(id, h.Sum64())
		p.ID = hex.EncodeToString(id)
	}
	if len(p.Username) == 0 {
		p.Username = p.ID
	}
	return nil
}

// Insert ...
func (p *Principal) Insert(ctx context.Context, db db.DB) error {
	return db.Create(p).Error
}

// AddFIDOKey ...
func (p *Principal) AddFIDOKey(fk *FIDOKey) error {
	p.FIDOKeys = append(p.FIDOKeys, fk)
	return nil
}

// Update ...
func (p *Principal) Update(ctx context.Context, db db.DB, values map[string]string) (string, error) {
	changes, err := p.ApplyChanges(values)
	if err != nil {
		return "", errors.Wrap(err, "updating record")
	}
	return changes, db.Save(p).Error
}

var _principalAllowedFields = map[string]bool{
	"state":       true,
	"displayName": true,
	"icon":        true,
}

var _principalAPIToDBFields = map[string]string{
	"displayName": "display_name",
	"createdAt":   "created_at",
}

// AllowedUpdateFields returns the fields that are mutable.
func (p *Principal) AllowedUpdateFields() map[string]bool {
	return _principalAllowedFields
}

// ApplyChanges updates the object with values found in the map and returns the "delta"
// of the changes.
func (p *Principal) ApplyChanges(values map[string]string) (string, error) {
	orig := new(Principal)
	*orig = *p
	allowed := p.AllowedUpdateFields()
	for k, v := range values {
		if _, ok := allowed[k]; !ok {
			return "", errors.Errorf("update field not allowed %s", k)
		}
		switch k {
		case "username":
			p.Username = v
		case "state":
			_, err := NewState(v)
			if err != nil {
				return "", err
			}
			p.State = v
		case "displayName":
			p.DisplayName = v
		case "icon":
			p.Icon = v
		}
	}
	return cmp.Diff(orig, p), nil
}

// CredentialList returns an array filled with all the principal's credentials.
func (p *Principal) CredentialList() []protocol.CredentialDescriptor {
	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range p.FIDOKeys {
		id, _ := hex.DecodeString(cred.ID)
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}
	return credentialExcludeList
}

// WebAuthnID return the principal's ID according to the RP.
func (p *Principal) WebAuthnID() []byte {
	id, _ := hex.DecodeString(p.ID)
	return id
}

// WebAuthnName return the principal's username according to the RP.
func (p *Principal) WebAuthnName() string {
	return p.Username
}

// WebAuthnDisplayName return the principal's display name according to the RP.
func (p *Principal) WebAuthnDisplayName() string {
	return p.DisplayName
}

// WebAuthnIcon return the principal's icon URL according to the RP.
func (p *Principal) WebAuthnIcon() string {
	return p.Icon
}

// WebAuthnCredentials returns credentials owned by the user.
func (p *Principal) WebAuthnCredentials() []webauthn.Credential {
	credentialList := []webauthn.Credential{}
	for _, key := range p.FIDOKeys {
		aaguid, err := uuid.Parse(key.AAGUID)
		if err != nil {
			panic(err)
		}
		id, _ := hex.DecodeString(key.ID)
		credentialList = append(credentialList, webauthn.Credential{
			ID:              id,
			PublicKey:       key.PublicKey,
			AttestationType: key.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid[:],
				SignCount: key.Nonce,
			},
		})
	}
	return credentialList
}

// PrincipalByID returns a `Principal` by id.
func PrincipalByID(ctx context.Context, db db.DB, id string, preload bool) (*Principal, error) {
	p := new(Principal)

	if preload {
		db = db.Set("gorm:auto_preload", true)
	}
	err := db.Where("id = ?", id).Or("username = ?", id).First(p).Error
	if err == gorm.ErrRecordNotFound {
		p = nil
		err = ErrRecordNotFound
	}
	return p, err
}

// PrincipalByUsername returns a `Principal` by username.
func PrincipalByUsername(ctx context.Context, db db.DB, username string, preload bool) (*Principal, error) {
	p := new(Principal)
	if preload {
		db = db.Set("gorm:auto_preload", true)
	}
	err := db.Where("username = ?", username).First(p).Error
	if err == gorm.ErrRecordNotFound {
		p = nil
		err = ErrRecordNotFound
	}
	return p, err
}

// Principals returns a list of principals.
func Principals(ctx context.Context, dbConn db.DB, params *util.APIParams) ([]*Principal, int64, error) {
	var count int64
	entries := make([]*Principal, 0)

	dbConn, countDB, _ := db.QueryStatement(dbConn, "principals_keycount", params, _principalAPIToDBFields)
	if _, ok := params.AndFilters["hasKeys"]; ok {
		delete(params.AndFilters, "hasKeys")
		dbConn = dbConn.Where("number_of_keys > 0")
		countDB = countDB.Where("number_of_keys > 0")
	}

	err := dbConn.Find(&entries).Error
	if err != nil {
		return entries, 0, err
	}
	// get total record count
	err = countDB.Select("count(*)").Row().Scan(&count)
	return entries, count, err
}
