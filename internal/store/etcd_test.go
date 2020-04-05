package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const etcdEndpoint = 31234

func Test_ETCDBasic(t *testing.T) {
	containerID, err := createStartETCDContainer()
	require.NoError(t, err)
	defer func() {
		_ = stopRemoveETCDContainer(containerID)
	}()
	ctx := context.Background()

	mgr, err := NewETCDManager(ctx, EtcdConfig{Endpoints: []string{fmt.Sprintf("http://127.0.0.1:%d", etcdEndpoint)}})
	require.NoError(t, err)

	err = mgr.Put(ctx, "foo", "bar", []byte{1}, 0)
	assert.NoError(t, err)
	err = mgr.Put(ctx, "foo", "baz", []byte{1}, 0)
	assert.NoError(t, err)

	_, err = mgr.Get(ctx, "foo", "bar")
	assert.NoError(t, err)

	_, err = mgr.Get(ctx, "bar", "foo")
	assert.Equal(t, ErrorNoRecord, err)

	results, total, err := mgr.List(ctx, "foo", 20, 1, true)
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, int64(2), total)
}

func Test_ETCDList(t *testing.T) {
	containerID, err := createStartETCDContainer()
	require.NoError(t, err)
	defer func() {
		_ = stopRemoveETCDContainer(containerID)
	}()
	ctx := context.Background()

	mgr, err := NewETCDManager(ctx, EtcdConfig{Endpoints: []string{fmt.Sprintf("http://127.0.0.1:%d", etcdEndpoint)}})
	require.NoError(t, err)

	for n := 1; n < 41; n++ {
		key := fmt.Sprintf("bar%02d", n)
		err = mgr.Put(ctx, "foo", key, []byte(fmt.Sprintf("value%02d", n)), 0)
		require.NoError(t, err)
	}

	results, total, err := mgr.List(ctx, "foo", 10, 1, true)
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, int64(40), total)
	require.Equal(t, "/foo/bar40", results[0].Key)
	require.Equal(t, "value40", string(results[0].Value))
	require.Equal(t, "/foo/bar31", results[9].Key)

	results, _, err = mgr.List(ctx, "foo", 10, 2, false)
	require.NoError(t, err)
	require.Equal(t, "/foo/bar11", results[0].Key)
	require.Equal(t, "/foo/bar20", results[9].Key)

	// Outside of available pages
	results, _, err = mgr.List(ctx, "foo", 10, 5, false)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Overflow
	results, _, err = mgr.List(ctx, "foo", 30, 2, true)
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "/foo/bar01", results[9].Key)
}

func Test_ETCDWatch(t *testing.T) {
	containerID, err := createStartETCDContainer()
	require.NoError(t, err)
	ctx := context.Background()

	mgr, err := NewETCDManager(context.Background(), EtcdConfig{Endpoints: []string{fmt.Sprintf("http://127.0.0.1:%d", etcdEndpoint)}})
	require.NoError(t, err)

	err = mgr.Put(ctx, "foo", "bar", []byte("hello"), 5)
	assert.NoError(t, err)

	//resultChan := mgr.WatchKey("foo", "bar")
	resultChan := mgr.Watch(ctx, "foo")
	done := make(chan bool)

	go func() {
		for {
			result := <-resultChan
			spew.Dump(result)
			if result.Type == OperationTypeDELETE {
				done <- true
			} else if result.Type == OperationTypePUT {
				assert.Equal(t, []byte("there"), result.Result.Value)
			}
		}
	}()

	time.Sleep(time.Second * 1)

	err = mgr.Put(ctx, "foo", "bar", []byte("there"), 5)
	assert.NoError(t, err)

	<-done

	err = stopRemoveETCDContainer(containerID)
	require.NoError(t, err)
}

func createStartETCDContainer() (string, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		fmt.Println("Unable to create docker client")
		panic(err)
	}

	hostBinding1 := nat.PortBinding{
		HostIP:   "0.0.0.0",
		HostPort: fmt.Sprintf("%d/tcp", etcdEndpoint),
	}
	hostBinding2 := nat.PortBinding{
		HostIP:   "0.0.0.0",
		HostPort: fmt.Sprintf("%d/tcp", etcdEndpoint+1),
	}
	containerPort1, err := nat.NewPort("tcp", fmt.Sprintf("%d", etcdEndpoint))
	if err != nil {
		return "", err
	}
	containerPort2, err := nat.NewPort("tcp", fmt.Sprintf("%d", etcdEndpoint+1))
	if err != nil {
		return "", err
	}
	if err != nil {
		return "", err
	}

	portBinding := nat.PortMap{
		containerPort1: []nat.PortBinding{hostBinding1},
		containerPort2: []nat.PortBinding{hostBinding2},
	}

	env := []string{
		"ETCD_DATA_DIR=/data",
		"ETCD_NAME=etcd01",
		fmt.Sprintf("ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:%d", etcdEndpoint),
		fmt.Sprintf("ETCD_LISTEN_PEER_URLS=http://0.0.0.0:%d", etcdEndpoint+1),
		fmt.Sprintf("ETCD_ADVERTISE_CLIENT_URLS=http://127.0.0.1:%d", etcdEndpoint),
		fmt.Sprintf("ETCD_INITIAL_ADVERTISE_PEER_URLS=http://127.0.0.1:%d", etcdEndpoint+1),
		fmt.Sprintf("ETCD_INITIAL_CLUSTER=etcd01=http://127.0.0.1:%d", etcdEndpoint+1),
	}
	cont, err := cli.ContainerCreate(
		context.Background(),
		&container.Config{
			Image: "quay.io/coreos/etcd:v3.3.12",
			Env:   env,
			ExposedPorts: nat.PortSet{
				nat.Port(fmt.Sprintf("%d/tcp", etcdEndpoint)):   {},
				nat.Port(fmt.Sprintf("%d/tcp", etcdEndpoint+1)): {},
			},
		},
		&container.HostConfig{
			PortBindings: portBinding,
		}, nil, "test_etcd")
	if err != nil {
		return "", err
	}

	err = cli.ContainerStart(context.Background(), cont.ID, types.ContainerStartOptions{})
	return cont.ID, err
}

func stopRemoveETCDContainer(ID string) error {
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}

	err = cli.ContainerStop(context.Background(), ID, nil)
	if err != nil {
		return err
	}
	return cli.ContainerRemove(context.Background(), ID, types.ContainerRemoveOptions{})
}
