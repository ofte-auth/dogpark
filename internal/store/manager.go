package store

import (
	"context"

	"github.com/pkg/errors"
)

// OperationType is the type of operation performed on a record
type OperationType int32

const (
	// OperationTypePUT Represents PUT storage operations
	OperationTypePUT OperationType = 0
	// OperationTypeDELETE Represents DELETE storage operations
	OperationTypeDELETE OperationType = 1
)

// WatchResult represents changes in a watched collection
type WatchResult struct {
	Result Result
	Type   OperationType
	Err    error
}

// Result represents a k/v result
type Result struct {
	Key   string
	Value []byte
}

// Manager defines a general interface for managing objects
type Manager interface {
	Close() error

	// General-purpose collection/key/value storage
	Put(ctx context.Context, collection string, key string, value []byte, ttlSeconds int64) error
	Delete(ctx context.Context, collection string, key string) error
	// Watch a collection for changes
	Watch(ctx context.Context, collection string) <-chan WatchResult
	// Watch a key for changes
	WatchKey(ctx context.Context, collection, key string) <-chan WatchResult

	Get(ctx context.Context, collection string, key string) ([]byte, error)
	Exists(ctx context.Context, collection string, key string) (bool, error)
	List(cctx context.Context, collection string, limit, page int64, newestFirst bool) ([]Result, int64, error)
}

// NewManager creates a new KV manager based on the type of config file supplied.
func NewManager(ctx context.Context, config interface{}) (Manager, error) {
	switch cfg := config.(type) {
	case EtcdConfig:
		return NewETCDManager(ctx, cfg)
	}
	return nil, errors.Errorf("no KV manager found for config type %T", config)
}
