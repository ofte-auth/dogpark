package model

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/jinzhu/gorm"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
)

// AAGUID represents a Authenticator Attestation GUID. AAGUIDs uniquely identify
// a group (>100k) of authenticators.
// See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html
//
// You can control whitelisting and blacklisting of AAGUIDs by updating an AAGUID's
// `State` variable. For instance, to block a AAGUID, update the a record's State variable
// to 'revoked'. This will prevent any authenticator with that AAGUID from authenticating.
// To whitelist one or more AAGUIDs, update a record's State variable to 'active'. Once one or more
// records have an 'active' State a whitelist is, in effect, created; authenticators with other AAGUIDs
// will not be able to authenticate. If `State` is empty or `issued`, the authenticator is neither explictly
// blacklisted nor whitelisted.
type AAGUID struct {
	ID       string `json:"id"`
	Label    string `json:"label" gorm:"index"`
	State    string `json:"state" gorm:"index"`
	Metadata []byte `json:"metadata"`
}

// AAGUIDByID returns a stored AAGUID by ID.
func AAGUIDByID(ctx context.Context, db db.DB, id string) (*AAGUID, error) {
	k := new(AAGUID)
	err := db.Where("id = ?", id).First(k).Error
	if err == gorm.ErrRecordNotFound {
		k = nil
		err = ErrRecordNotFound
	}
	return k, err
}

// Update ...
func (guid *AAGUID) Update(ctx context.Context, db db.DB, values map[string]string) (string, error) {
	changes, err := guid.ApplyChanges(values)
	if err != nil {
		return "", errors.Wrap(err, "updating record")
	}
	return changes, db.Save(guid).Error
}

// AllowedUpdateFields returns the fields that are mutable.
func (guid *AAGUID) AllowedUpdateFields() map[string]bool {
	return map[string]bool{"state": true}
}

// ApplyChanges updates the object with values found in the map and returns
// a description of the changes.
func (guid *AAGUID) ApplyChanges(values map[string]string) (string, error) {
	orig := new(AAGUID)
	*orig = *guid
	allowed := guid.AllowedUpdateFields()
	for k, v := range values {
		if _, ok := allowed[k]; !ok {
			continue
		}
		switch k {
		case "state":
			_, err := NewState(v)
			if err != nil {
				return "", err
			}
			guid.State = v
		}
	}
	return cmp.Diff(orig, guid), nil
}

// AAGUIDs returns a list of AAGUIDs.
func AAGUIDs(ctx context.Context, dbConn db.DB, params *util.APIParams) ([]*AAGUID, int64, error) {
	var count int64
	entries := make([]*AAGUID, 0)

	dbConn, countDB, _ := db.QueryStatement(dbConn, "aa_guids", params, nil)

	err := dbConn.Find(&entries).Error
	if err != nil {
		return entries, 0, err
	}
	// get total record count
	err = countDB.Select("count(*)").Row().Scan(&count)

	return entries, count, err
}

// WhitelistAAGUIDs returns a list of all AAGUIDs that are in the whitelist.
func WhitelistAAGUIDs(ctx context.Context, db db.DB) (util.StringSet, error) {
	results := make(util.StringSet)
	args := map[string]interface{}{"state": StateActive}
	rows, err := db.New().Table("aa_guids").Where(args).Select("id").Rows()
	defer func() {
		_ = rows.Close()
	}()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		err := rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		results.Add(id)
	}
	return results, nil
}

// BlacklistAAGUIDs returns a list of all AAGUIDs that are in the blacklist.
func BlacklistAAGUIDs(ctx context.Context, db db.DB) (util.StringSet, error) {
	results := make(util.StringSet)
	args := map[string]interface{}{"state": StateRevoked}
	rows, err := db.New().Table("aa_guids").Where(args).Select("id").Rows()
	defer func() {
		_ = rows.Close()
	}()
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		err := rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		results.Add(id)
	}
	return results, nil
}
