package service

import (
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nullMDSToken = "ffffffffffffffffffffffffffffffffffffffffffffffff"

func TestUpdateFIDOMetadata(t *testing.T) {
	dbConn, err := db.GetTestDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip("Database not available, skipping")
			return
		}
		t.Fatal(err)
	}
	defer func() {
		_ = db.CloseConnection(dbConn)
	}()

	// Update this with your token, see https://fidoalliance.org/metadata/
	mdsToken := nullMDSToken

	err = UpdateFIDOMetadata(dbConn, "d384db22-4d50-ebde-2eac-5765cf1e2a44", mdsToken)
	if mdsToken != nullMDSToken {
		assert.NoError(t, err)
	}
	err = UpdateFIDOMetadata(dbConn, "", mdsToken)
	assert.Error(t, err)
	require.IsType(t, validator.ValidationErrors{}, err)
	assert.Contains(t, err.Error(), "failed on the 'required' tag")
}
