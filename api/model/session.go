package model

import (
	"github.com/ofte-auth/dogpark/internal/geo"
)

// Session defines data describing an a11r session.
type Session struct {
	geo.GeoEntry

	SessionID string `json:"session"`
	State     string `json:"state"`
	FIDOKeyID string `json:"keyId"`
	AAGUID    string `json:"aaguid"`
	UserID    string `json:"userId"`
	Username  string `json:"username"`
	Age       string `json:"age"`
}
