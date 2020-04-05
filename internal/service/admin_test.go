package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ofte-auth/dogpark/internal/model"

	"github.com/ofte-auth/dogpark/internal/util"

	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AdminService_AddAndUpdatePrincipal(t *testing.T) {
	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAdminService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	principal, err := service.AddPrincipal(ctx, map[string]string{
		"username":    "joe@example.com",
		"displayName": "joe",
		"icon":        "http://example.com/example.gif",
	})
	assert.NoError(err)
	assert.NotEmpty(principal.ID)

	principal, err = service.PrincipalByUsername(ctx, "joe@example.com")
	assert.NoError(err)
	assert.Equal("joe@example.com", principal.Username)

	principal, err = service.AddPrincipal(ctx, map[string]string{
		"id":          "12345678",
		"username":    "joe2@example.com",
		"displayName": "joe",
		"icon":        "http://example.com/example.gif",
	})
	assert.NoError(err)
	assert.Equal("active", principal.State)

	_, _, err = service.UpdatePrincipal(ctx, principal.ID, map[string]string{"displayName": "Abe"})
	assert.NoError(err)

	principal, err = service.Principal(ctx, principal.ID)
	assert.NoError(err)
	assert.Equal("Abe", principal.DisplayName)

	_, _, err = service.UpdatePrincipal(ctx, principal.ID, map[string]string{"foo": "bar"})
	assert.Error(err)
	assert.Equal("update field not allowed foo", err.Error())
}

func Test_ListPrincipals(t *testing.T) {
	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAdminService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	for _, v := range []string{"bill", "larry", "ada"} {
		principal, err := service.AddPrincipal(ctx, map[string]string{
			"username":    fmt.Sprintf("%s@example.com", v),
			"displayName": v,
		})
		assert.NoError(err)
		assert.NotEmpty(principal.ID)
	}

	l, count, err := service.Principals(ctx, util.DefaultAPIParams())
	assert.NoError(err)
	assert.Len(l, 3)
	assert.Equal(int64(3), count)

	l, count, err = service.Principals(ctx, &util.APIParams{
		AndFilters: map[string]interface{}{"state": "revoked"},
	})
	assert.NoError(err)
	assert.NotNil(l)
	assert.Equal(int64(0), count)

	l, count, err = service.Principals(ctx, &util.APIParams{
		AndFilters: map[string]interface{}{
			"username":    "bill@example.com",
			"displayName": "bill",
		},
	})
	assert.NoError(err)
	assert.NotNil(l)
	assert.Equal(int64(1), count)
}

func Test_AddAndUpdateAAGUIDs(t *testing.T) {
	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAdminService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	uuid := "96a565a1-8c2c-406f-879f-573cb0f9cc15"
	_, err = service.AddAAGUID(ctx, map[string]string{
		"id":    uuid,
		"label": "test",
	})

	assert.NoError(err)

	l, count, err := service.AAGUIDs(ctx, util.DefaultAPIParams())
	assert.Equal(int64(1), count)
	assert.NoError(err)
	assert.Len(l, 1)

}

func Test_AAGUIDWhiteAndBlackList(t *testing.T) {

	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAdminService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	uuid := "96a565a1-8c2c-406f-879f-573cb0f9cc15"
	_, err = service.AddAAGUID(ctx, map[string]string{
		"id":    uuid,
		"label": "test",
		"state": "active",
	})
	assert.NoError(err)

	whitelist, err := service.AAGUIDWhitelist(ctx)
	assert.NoError(err)
	assert.True(whitelist.Has(uuid))

	aaguid, _, err := service.UpdateAAGUID(ctx, uuid, map[string]string{"state": "revoked"})
	assert.NoError(err)
	assert.Equal("revoked", aaguid.State)

	blacklist, err := service.AAGUIDBlacklist(ctx)
	assert.NoError(err)
	assert.True(blacklist.Has(uuid))
}

func getTestAdminService(ctx context.Context, t *testing.T) (Admin, error) {
	db, err := db.GetTestDB()
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			t.Skip("Database not available, skipping")
			return nil, err
		}
		t.Fatal(err)
		return nil, err
	}
	err = model.Migrate(db)
	if err != nil {
		return nil, err
	}

	kv, err := store.NewETCDMockManager()
	require.NoError(t, err)

	service, err := NewAdminService(ctx, OptionDB(db), OptionKV(kv))
	require.NoError(t, err)
	return service, err
}
