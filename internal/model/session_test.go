package model

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ofte-auth/dogpark/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewSession(t *testing.T) {
	type args struct {
		principalID string
		fidoKeyID   string
		ipaddr      string
		userAgent   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Happy Path",
			args: args{
				principalID: "123456789",
				fidoKeyID:   "123456789",
				ipaddr:      "127.0.0.1",
				userAgent:   "test",
			},
			wantErr: false,
		},
		{
			name: "Invalid principal ID",
			args: args{
				principalID: "1234567",
				fidoKeyID:   "123456789",
				ipaddr:      "127.0.0.1",
				userAgent:   "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSession(tt.args.principalID, tt.args.fidoKeyID, uuid.New().String(), tt.args.ipaddr, tt.args.userAgent)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if !reflect.DeepEqual(got.FIDOKeyID, tt.args.fidoKeyID) {
					t.Errorf("NewSession() = %v", got)
				}
				if time.Since(got.CreatedAt) > time.Second {
					t.Errorf("NewSession() = %v, creation time anomaly", got)
				}
			}
		})
	}
}

func Test_SessionPut(t *testing.T) {
	ctx := context.Background()
	session, err := NewSession("pRiNciPaL", "FiDoKeYId", uuid.New().String(), "8.8.8.8", "Testing")
	require.NoError(t, err)
	manager, err := store.NewETCDMockManager()
	require.NoError(t, err)

	err = session.Put(ctx, manager, 30)
	assert.NoError(t, err)

	_, err = SessionByID(ctx, manager, session.ID)
	assert.NoError(t, err)

	_ = manager.Close()
}
