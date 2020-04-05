package model

import (
	"strings"

	"github.com/pkg/errors"
)

// State ...
type State int

// Constants for State
const (
	Issued State = iota
	Active
	Revoked

	StateIssued  = "issued"
	StateActive  = "active"
	StateRevoked = "revoked"
)

func (s State) String() string {
	return [...]string{
		StateIssued,
		StateActive,
		StateRevoked,
	}[s]
}

// NewState creates a new `State` from a string.
func NewState(state string) (State, error) {
	switch strings.ToLower(state) {
	case "issued":
		return Issued, nil
	case "active":
		return Active, nil
	case "revoked":
		return Revoked, nil
	default:
		return -1, errors.Errorf("invalid state %s", state)
	}
}
