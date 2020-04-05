package model

// Principal defines a user.
type Principal struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Icon        string `json:"icon,omitempty"`
	CASessionID string `json:"caSessionID,omitempty"`
}
