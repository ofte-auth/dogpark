package model

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/stretchr/testify/assert"
)

func Test_CreateAuditEntry(t *testing.T) {
	dbConn, err := db.GetTestDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip("Database not available, skipping")
			return
		}
		t.Fatal(err)
	}
	err = Migrate(dbConn)
	assert.NoError(t, err)
	defer func() {
		_ = db.CloseConnection(dbConn)
	}()

	entry := &AuditEntry{
		Action: "create",
		Data:   "foo",
	}

	err = dbConn.Create(entry).Error
	assert.NoError(t, err)

	var entries []AuditEntry
	dbConn.Where("action = ?", "create").Find(&entries)

	assert.True(t, len(entries) > 0)

	_, err = AuditEntryByID(dbConn, 0xffffffff)
	assert.Error(t, err)
}

func Test_SearchAuditEntry(t *testing.T) {
	dbConn, err := db.GetTestDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip("Database not available, skipping")
			return
		}
		t.Fatal(err)
	}
	err = Migrate(dbConn)
	assert.NoError(t, err)
	defer func() {
		_ = db.CloseConnection(dbConn)
	}()

	for n := 0; n < 100; n++ {
		entry := &AuditEntry{
			Data: "foo",
		}
		if n%2 == 0 {
			entry.Action = "create"
			entry.PrincipalID = "bill"
		} else {
			entry.Action = "delete"
			entry.PrincipalID = "larry"
		}
		err = dbConn.Create(entry).Error
		assert.NoError(t, err)
	}

	ctx := context.Background()
	params := &util.APIParams{
		AndFilters: map[string]interface{}{"action": "create"},
		Limit:      10,
		Page:       1,
	}
	entries, count, err := AuditEntries(ctx, dbConn, params)
	assert.NoError(t, err)
	assert.Equal(t, int64(50), count)
	assert.Equal(t, int64(1), entries[0].ID)

	params.Page = 5
	entries, count, err = AuditEntries(ctx, dbConn, params)
	assert.NoError(t, err)
	assert.Equal(t, int64(50), count)
	assert.Equal(t, int64(81), entries[0].ID)

	params = util.DefaultAPIParams()
	params.CreatedAfter = time.Now().Add(-1 * time.Minute)
	_, count, err = AuditEntries(ctx, dbConn, params)
	assert.NoError(t, err)
	assert.Equal(t, int64(100), count)

	params = util.DefaultAPIParams()
	params.CreatedAfter = time.Now().Add(1 * time.Minute)
	_, count, err = AuditEntries(ctx, dbConn, params)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)
}
