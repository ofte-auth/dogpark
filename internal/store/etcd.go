package store

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/etcdserver/api/v3rpc/rpctypes"
	"github.com/coreos/etcd/integration"
	"github.com/ofte-auth/dogpark/internal/util"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	config "github.com/spf13/viper"
)

// EtcdConfig defines etcd store configuration info
type EtcdConfig struct {
	Endpoints []string
}

type etcdManager struct {
	cli     *clientv3.Client
	kv      clientv3.KV
	watcher clientv3.Watcher
}

// NewETCDManager returns etcd store implementation
func NewETCDManager(ctx context.Context, config EtcdConfig) (Manager, error) {
	if len(config.Endpoints) == 0 {
		err := errors.New("no endpoints in config")
		return nil, util.RetryStop{Err: err}
	}
	cfg := clientv3.Config{
		Context:     ctx,
		Endpoints:   config.Endpoints,
		DialTimeout: 10 * time.Second,
	}
	cli, err := clientv3.New(cfg)
	if err != nil {
		return nil, err
	}

	mgr := &etcdManager{
		cli:     cli,
		kv:      clientv3.NewKV(cli),
		watcher: clientv3.NewWatcher(cli),
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = cli.Get(ctx, "ping")
	if err == context.DeadlineExceeded {
		return nil, err
	}
	return mgr, nil
}

// NewETCDMockManager returns a manager suitable for test environments.
func NewETCDMockManager() (Manager, error) {

	cfg := integration.ClusterConfig{Size: 1}
	cluster := integration.NewClusterV3(nil, &cfg)
	cli := cluster.RandClient()

	return &etcdManager{
		cli:     cli,
		kv:      clientv3.NewKV(cli),
		watcher: clientv3.NewWatcher(cli),
	}, nil
}

// Close ...
func (mgr *etcdManager) Close() error {
	if mgr.watcher != nil {
		_ = mgr.watcher.Close()
	}
	if mgr.cli != nil {
		return mgr.cli.Close()
	}
	return nil
}

// Put ...
func (mgr *etcdManager) Put(ctx context.Context, collection string, key string, value []byte, ttlSeconds int64) error {
	var err error
	if ttlSeconds > 0 {
		var resp *clientv3.LeaseGrantResponse
		var op clientv3.OpOption
		resp, err = mgr.cli.Grant(ctx, ttlSeconds)
		if err != nil {
			return errors.Wrap(err, "obtaining etcd ttl lease")
		}
		op = clientv3.WithLease(resp.ID)
		_, err = mgr.kv.Put(ctx, assembleKey(collection, key), string(value[:]), op)
	} else {
		_, err = mgr.kv.Put(ctx, assembleKey(collection, key), string(value[:]))
	}
	return err
}

// Delete ...
func (mgr *etcdManager) Delete(ctx context.Context, collection string, key string) error {
	_, err := mgr.kv.Delete(ctx, assembleKey(collection, key), clientv3.WithPrefix())
	return err
}

// Watch ...
func (mgr *etcdManager) Watch(ctx context.Context, collection string) <-chan WatchResult {
	return mgr.watch(ctx, assembleDir(collection))
}

func (mgr *etcdManager) watch(ctx context.Context, key string) <-chan WatchResult {
	ch := make(chan WatchResult)
	wch := mgr.watcher.Watch(ctx, key, clientv3.WithPrefix())

	go func() {
		for resp := range wch {
			if err := resp.Err(); err != nil {
				ch <- WatchResult{Err: err}
				break
			}

			for _, e := range resp.Events {
				var opType OperationType

				switch e.Type {
				case clientv3.EventTypePut:
					opType = OperationTypePUT
				case clientv3.EventTypeDelete:
					opType = OperationTypeDELETE
				default:
					log.Warningf("etcd event type not supported: %v", e.Type)
				}

				res := Result{
					Key:   string(e.Kv.Key),
					Value: e.Kv.Value,
				}
				ch <- WatchResult{Type: opType, Result: res}
			}
		}
	}()

	return ch
}

func (mgr *etcdManager) WatchKey(ctx context.Context, collection, key string) <-chan WatchResult {
	return mgr.watch(ctx, assembleKey(collection, key))
}

// ErrorNoRecord ...
var ErrorNoRecord = errors.New("no key found")

func (mgr *etcdManager) Get(ctx context.Context, collection string, key string) ([]byte, error) {
	resp, err := mgr.kv.Get(ctx, assembleKey(collection, key))
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) != 1 {
		return nil, ErrorNoRecord
	}
	return resp.Kvs[0].Value, nil
}

func (mgr *etcdManager) Exists(ctx context.Context, collection string, key string) (bool, error) {
	resp, err := mgr.kv.Get(ctx, assembleKey(collection, key))
	if err == rpctypes.ErrGRPCKeyNotFound {
		return false, nil
	}
	if resp != nil && resp.Count > 0 {
		return true, nil
	}
	return false, errors.Wrap(err, "error fetching key from store")
}

// List returns `limit` entries from `page` (1-based). It returns the total records ordered by
// mod revision along with the results.
func (mgr *etcdManager) List(ctx context.Context, collection string, limit, page int64, newestFirst bool) ([]Result, int64, error) {
	opts := []clientv3.OpOption{clientv3.WithPrefix()}
	if page <= 0 {
		page = 1
	}
	if limit <= 0 || limit > 0xffff {
		limit = 100
	}
	max := limit * page
	opts = append(opts, clientv3.WithLimit(max))
	sortByOrder := clientv3.SortAscend
	if newestFirst {
		sortByOrder = clientv3.SortDescend
	}
	opts = append(opts, clientv3.WithSort(clientv3.SortByModRevision, sortByOrder))
	opts = append(opts, clientv3.WithKeysOnly())
	resp, err := mgr.kv.Get(ctx, assembleDir(collection), opts...)
	if err != nil {
		return nil, 0, err
	}
	arr := make([]Result, 0)
	index := limit * (page - 1)
	total := int64(len(resp.Kvs))
	if index < total {
		lastIndex := index + limit + 1
		if lastIndex > total {
			lastIndex = total
		}
		for _, v := range resp.Kvs[index:lastIndex] {
			resp, err := mgr.kv.Get(ctx, string(v.Key))
			if err != nil {
				return nil, 0, errors.Wrap(err, "getting key from store using list entry")
			}
			if len(resp.Kvs) != 1 {
				// value ejected/deleted from store
				continue
			}
			arr = append(arr, Result{string(v.Key), resp.Kvs[0].Value})
		}
	}

	opts = []clientv3.OpOption{
		clientv3.WithPrefix(),
		clientv3.WithCountOnly(),
	}
	resp, err = mgr.kv.Get(ctx, assembleDir(collection), opts...)
	if err != nil {
		return nil, 0, err
	}
	total = resp.Count
	return arr, total, nil
}

func assembleDir(collection string) string {
	return fmt.Sprintf("/%s", collection)
}

func assembleKey(collection, key string) string {
	return fmt.Sprintf("%s/%s", assembleDir(collection), key)
}

func init() {
	config.SetDefault("KV_ENDPOINTS", []string{"http://localhost:2379"})
}
