package model

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func Test_PrincipalUpdate(t *testing.T) {
	assert := assert.New(t)

	p := NewPrincipal("", "foo@bar.com", StateActive, "Bill Gates", "http:/pic.org/m")

	diff, err := p.ApplyChanges(map[string]string{"displayName": "Steve Jobs"})
	assert.NoError(err)
	assert.Contains(diff, "\"Bill Gates\"")

	_, err = p.ApplyChanges(map[string]string{"id": "not_allowed"})
	assert.Error(err)
}

func Test_PrincipalAndArtifacts(t *testing.T) {

	ctx := context.Background()
	assert := assert.New(t)
	dbConn, err := db.GetTestDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip("Database not available, skipping")
			return
		}
		t.Fatal(err)
	}
	err = Migrate(dbConn)
	assert.NoError(err)
	defer func() {
		_ = db.CloseConnection(dbConn)
	}()

	p := NewPrincipal("", "matthew@ofte.io", StateIssued, "Matthew McNeely", "http://pic.org/m")
	err = dbConn.FirstOrCreate(p).Error
	assert.NoError(err)

	t.Run("GetPrincipal", func(t *testing.T) {
		p, err := PrincipalByUsername(ctx, dbConn, "matthew@ofte.io", true)
		assert.NoError(err)
		assert.Equal("http://pic.org/m", p.Icon, "Expect to retrieve attributes")
	})
	t.Run("AddFIDOKey", func(t *testing.T) {
		p, err := PrincipalByUsername(ctx, dbConn, "matthew@ofte.io", true)
		assert.NoError(err)
		fidoKey := &FIDOKey{
			ID:          "some-FIDO-key",
			PrincipalID: p.ID,
			AAGUID:      uuid.New().String(),
		}
		err = dbConn.Save(fidoKey).Error
		assert.NoError(err)

		p, err = PrincipalByUsername(ctx, dbConn, "matthew@ofte.io", true)
		assert.NoError(err)
		require.Len(t, p.FIDOKeys, 1)
		assert.Equal("some-FIDO-key", p.FIDOKeys[0].ID)
	})
}
