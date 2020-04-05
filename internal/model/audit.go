package model

import (
	"context"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/util"
)

// AuditEntry defines auditing entries stored in the audit table.
type AuditEntry struct {
	ID                int64     `json:"id" gorm:"auto_increment;unique_index"`
	Group             string    `json:"group" gorm:"index"`
	Anomaly           string    `json:"anomaly" gorm:"index"`
	FidoKeyID         string    `json:"fidoKeyId" gorm:"index"`
	FidoAAGUID        string    `json:"fidoAAGUID" gorm:"index"`
	PrincipalID       string    `json:"principalId" gorm:"index"`
	PrincipalUsername string    `json:"principalUsername" gorm:"index"`
	SessionID         string    `json:"sessionId" gorm:"index"`
	Action            string    `json:"action" gorm:"index"`
	Data              string    `json:"data,omitempty"`
	IPAddr            string    `json:"ipAaddr,omitempty" gorm:"index"`
	UserAgent         string    `json:"userAgent,omitempty"`
	Latitude          float64   `json:"latitude"`
	Longitude         float64   `json:"longitude"`
	Country           string    `json:"country,omitempty" gorm:"index"`
	Region            string    `json:"region,omitempty" gorm:"index"`
	City              string    `json:"city,omitempty" gorm:"index"`
	CreatedAt         time.Time `json:"createdAt" gorm:"index"`
}

var _auditAPIToDBFields = map[string]string{
	"createdAt":         "created_at",
	"keyId":             "fido_key_id",
	"aaguid":            "fido_aa_guid",
	"principalId":       "principal_id",
	"principalUsername": "principal_username",
	"sessionId":         "session_id",
	"ipAddr":            "ip_addr",
}

// AuditEntryByID retrieves audit entries by ID.
func AuditEntryByID(db *gorm.DB, id int64) (*AuditEntry, error) {
	ae := &AuditEntry{
		ID: id,
	}
	err := db.First(ae).Error
	if err == gorm.ErrRecordNotFound {
		ae = nil
		err = ErrRecordNotFound
	}
	return ae, err
}

// AuditEntries returns audit entries.
func AuditEntries(ctx context.Context, dbConn db.DB, params *util.APIParams) ([]*AuditEntry, int64, error) {
	var count int64
	entries := make([]*AuditEntry, 0)

	dbConn, countDB, _ := db.QueryStatement(dbConn, "audit_entries", params, _auditAPIToDBFields)
	if _, ok := params.AndFilters["isAnomaly"]; ok {
		delete(params.AndFilters, "isAnomaly")
		dbConn = dbConn.Where("anomaly != ''")
		countDB = countDB.Where("anomaly != ''")
	}

	err := dbConn.Find(&entries).Error
	if err != nil {
		return entries, 0, err
	}
	// get total record count
	err = countDB.Select("count(*)").Row().Scan(&count)
	return entries, count, err
}
