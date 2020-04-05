package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/ofte-auth/dogpark/internal/db"
	"github.com/ofte-auth/dogpark/internal/model"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AuthService_AddAndUpdatePrincipal(t *testing.T) {
	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAuthService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	principal, err := service.GetOrCreatePrincipal(ctx, map[string]string{
		"username":    "joe@example.com",
		"displayName": "joe",
		"icon":        "http://example.com/example.gif",
	})
	assert.Nil(err)
	assert.NotEmpty(principal.ID)
}

func Test_AuthService_GetOrCreatePrincipal(t *testing.T) {
	ctx := context.Background()

	service, err := getTestAuthService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	type args struct {
		params map[string]string
	}
	tests := []struct {
		name string
		args args
		want *model.Principal
		err  *APIError
	}{
		{
			name: "Happy path",
			args: args{
				params: map[string]string{
					"username":    "joe@example.com",
					"displayName": "joe",
					"icon":        "http://example.com/example.gif",
				},
			},
			want: &model.Principal{
				ID:          "4a3b3fb154bd089f",
				Username:    "joe@example.com",
				DisplayName: "joe",
				Icon:        "http://example.com/example.gif",
				State:       model.StateActive,
			},
			err: nil,
		},
		{
			name: "ID supplied",
			args: args{
				params: map[string]string{
					"id":          "87654321",
					"username":    "joe@example.com",
					"displayName": "joe",
					"icon":        "http://example.com/example.gif",
				},
			},
			want: &model.Principal{
				ID:          "87654321",
				Username:    "joe@example.com",
				DisplayName: "joe",
				Icon:        "http://example.com/example.gif",
				State:       model.StateActive,
			},
			err: nil,
		},
		{
			name: "Username not supplied",
			args: args{
				params: map[string]string{
					"id":          "12345678",
					"displayName": "joe",
					"icon":        "http://example.com/example.gif",
				},
			},
			want: &model.Principal{
				ID:          "12345678",
				Username:    "12345678",
				DisplayName: "joe",
				Icon:        "http://example.com/example.gif",
				State:       model.StateActive,
			},
			err: nil,
		},
		{
			name: "Duplicate record should work",
			args: args{
				params: map[string]string{
					"id":          "12345678",
					"displayName": "joe",
					"icon":        "http://example.com/example.gif",
				},
			},
			want: &model.Principal{
				ID:          "12345678",
				Username:    "12345678",
				DisplayName: "joe",
				Icon:        "http://example.com/example.gif",
				State:       model.StateActive,
				FIDOKeys:    []*model.FIDOKey{},
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := service.GetOrCreatePrincipal(ctx, tt.args.params)
			if p != nil {
				tt.want.CreatedAt = p.CreatedAt
			}
			if !reflect.DeepEqual(p, tt.want) {
				t.Errorf("authService.GetOrCreatePrincipal() got = %v, want %v", p, tt.want)
				fmt.Println(cmp.Diff(tt.want, p))
			}
			if !reflect.DeepEqual(err, tt.err) {
				t.Errorf("authService.GetOrCreatePrincipal() got1 = %v, want %v", err, tt.err)
			}
		})
	}
}

func Test_FIDORegisterAndLogin(t *testing.T) {
	ctx := context.Background()
	assert := assert.New(t)

	service, err := getTestAuthService(ctx, t)
	if err != nil {
		return
	}
	defer func() {
		service.Stop()
	}()

	principal, err := service.GetOrCreatePrincipal(ctx, map[string]string{
		"username":    "matthew@ofte.io",
		"displayName": "matthew",
		"icon":        "http://example.com/example.gif",
	})
	assert.Nil(err)
	assert.NotEmpty(principal.ID)

	credentialCreation, err := service.StartFIDORegistration(ctx, principal.Username)
	assert.Nil(err)
	assert.Equal("localhost", credentialCreation.Response.RelyingParty.CredentialEntity.Name)

	id, _ := hex.DecodeString(principal.ID)
	mockSessionData := webauthn.SessionData{
		UserID:    id,
		Challenge: regChallenge,
	}
	marshaledData, err := json.Marshal(mockSessionData)
	assert.Nil(err)
	err = service.(*authService).kv.Put(ctx, CollectionPendingFIDORegistration, principal.Username, marshaledData, 30)
	assert.Nil(err)

	r := new(http.Request)
	r.Body = ioutil.NopCloser(strings.NewReader(mockCreationData))
	key, err := service.FinishFIDORegistration(ctx, principal.Username, r)
	assert.Nil(err)

	assert.Equal(key.AAGUID, "b92c3f9a-c014-4056-887f-140a2501163b")
	assert.Contains(key.CertCommonName, "Yubico U2F Root")

	credAssertion, err := service.StartFIDOLogin(ctx, principal.Username)
	assert.Nil(err)
	assert.Equal("localhost", credAssertion.Response.RelyingPartyID)

	mockSessionData.Challenge = loginChallenge
	marshaledData, err = json.Marshal(mockSessionData)
	assert.Nil(err)
	err = service.(*authService).kv.Put(ctx, CollectionPendingFIDOLogin, principal.Username, marshaledData, 30)
	assert.Nil(err)

	r = new(http.Request)
	r.Body = ioutil.NopCloser(strings.NewReader(mockLoginData))
	p, err := service.FinishFIDOLogin(ctx, principal.Username, r)
	assert.Nil(err)
	assert.NotNil(p)
}

func getTestAuthService(ctx context.Context, t *testing.T) (Auth, error) {
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

	service, err := NewAuthService(ctx,
		OptionDB(db),
		OptionKV(kv),
		OptionRP("localhost", "localhost", "https://localhost:8888"),
	)
	require.NoError(t, err)
	return service, err
}

const (
	regChallenge     = "cZEA3K0oOaendChzB2R7f6P9wuxw7_7HRLbtsaFtq7k"
	loginChallenge   = "KduLT5CggERDlv3qQIDYzU2At7QMbCjXgsBP0StgDl4"
	mockCreationData = `{"id":"IpSQ7UnDo19oEqSTIDKV73mW3j3VBmtKvNiWvrxSNfQW8rKazU9j22p3oiYkSewWkbq77nVs0vKIlog-mYiZ_g","rawId":"IpSQ7UnDo19oEqSTIDKV73mW3j3VBmtKvNiWvrxSNfQW8rKazU9j22p3oiYkSewWkbq77nVs0vKIlog-mYiZ_g","type":"public-key","response":{"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgKG9puBQ4PVrOF63D4AAvwqcP6uNOf0ZHoQ7IzsU8Wa8CIB0jSvEqvLkY_rChqLQ4hYpKY0OqTVprGNLn97YbYeRBY3g1Y4FZAsIwggK-MIIBpqADAgECAgRAAnmoMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxMDczOTA0MDQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXLcOpmwT8r_g_5OE0LNDIEjNoLb7h1AbcpvmzU1oBq3gUmZ2rf3Uby5RZE8Sd2VPKvDQj5bMVTu18UUVv76d0KNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQuSw_msAUQFaIfxQKJQEWOzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCyh-RGBqjevMATMvXGypDOMTAmC493RiBfGtSOt4OjG8uRBoWUyte1pNumOBN-idM-Kn-2sXA1cvsIKCycbBQa2O9B18Su4YxU9Yv98cf_33qSEMo6vwpW-SfjVbykcrN7M6btWvuxwsYQMI5as6wmuz1Dzv8TPuAXtYBGnTXml1DySELmYBd5DXNuBOu_7-S2JE0ccR2zDvkwlOqV5X2fTWMdVJ7z7wnuWxnEF8JOzT-5i1D8KrV92mfcnSZ6Qa12ZrUJWvgiVATSmSx72qc8TtYKxnZODGOV2DOFBP-VzSHUqgAzSYKuuHMmxr4TMvE7Eq6k3-jp1vjduDgDlfmIaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAABuSw_msAUQFaIfxQKJQEWOwBAIpSQ7UnDo19oEqSTIDKV73mW3j3VBmtKvNiWvrxSNfQW8rKazU9j22p3oiYkSewWkbq77nVs0vKIlog-mYiZ_qUBAgMmIAEhWCBXYI4v-KAjJt8m-36gxzCWa7bJiITBPMbnE3s2xbBrTiJYILgfKHtCACl-lNOO90Vg8QT19_6ylUkjCIJ9ks8fBfJP","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY1pFQTNLMG9PYWVuZENoekIyUjdmNlA5d3V4dzdfN0hSTGJ0c2FGdHE3ayIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg4ODgiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"}}`
	mockLoginData    = `{"id":"IpSQ7UnDo19oEqSTIDKV73mW3j3VBmtKvNiWvrxSNfQW8rKazU9j22p3oiYkSewWkbq77nVs0vKIlog-mYiZ_g","rawId":"IpSQ7UnDo19oEqSTIDKV73mW3j3VBmtKvNiWvrxSNfQW8rKazU9j22p3oiYkSewWkbq77nVs0vKIlog-mYiZ_g","type":"public-key","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABA","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS2R1TFQ1Q2dnRVJEbHYzcVFJRFl6VTJBdDdRTWJDalhnc0JQMFN0Z0RsNCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg4ODgiLCJjcm9zc09yaWdpbiI6ZmFsc2V9","signature":"MEUCIGe-0KOxgT6YF18dvzCOkNto3qFbqYLp01j9kWboYDiWAiEAmbDo4MwheBIVwfkXAGHPlf0RylBioEgB_CYYtGBNVuw","userHandle":""}}`
)
