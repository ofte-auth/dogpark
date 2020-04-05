package service

// ContextKey is a type for context key values.
type ContextKey int

// Consts for context keys
const (
	ContextError ContextKey = iota
	ContextIPAddr
	ContextUserAgent
)
