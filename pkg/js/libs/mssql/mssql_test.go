package mssql

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	gomssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestConnectionStringDoesNotTreatDatabaseNameAsDriverOptions(t *testing.T) {
	dbName := "master&encrypt=true&certificate=/tmp/nuclei-mssql-test.pem" +
		"&authenticator=krb5" +
		"&krb5-configfile=/tmp/krb5.conf" +
		"&krb5-keytabfile=/tmp/krb5.keytab" +
		"&krb5-credcachefile=/tmp/krb5.ccache"

	cfg, err := msdsn.Parse(mssqlConnString("127.0.0.1:1433", "user", "password", dbName))
	require.NoError(t, err)

	require.Equal(t, dbName, cfg.Database)
	require.Equal(t, "30", cfg.Parameters["connection timeout"])
	require.NotContains(t, cfg.Parameters, "encrypt")
	require.NotContains(t, cfg.Parameters, "certificate")
	require.NotContains(t, cfg.Parameters, "authenticator")
	require.NotContains(t, cfg.Parameters, "krb5-configfile")
	require.NotContains(t, cfg.Parameters, "krb5-keytabfile")
	require.NotContains(t, cfg.Parameters, "krb5-credcachefile")
}

func TestConnectionStringKeepsPlainDatabaseName(t *testing.T) {
	cfg, err := msdsn.Parse(mssqlConnString("127.0.0.1:1433", "user", "password", "master"))
	require.NoError(t, err)

	require.Equal(t, "master", cfg.Database)
}

func TestOpenDBUsesCustomFastdialer(t *testing.T) {
	execID := "mssql-opendb-test"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	db, err := openDB(execID, "127.0.0.1:1433", "user", "pass", "master")
	require.NoError(t, err)
	require.NotNil(t, db)
	_ = db.Close()
}

func TestMssqlDialerEnforcesNetworkPolicy(t *testing.T) {
	execID := "mssql-policy-test"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: goflags.StringSlice{"denied.host"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	dialer := &mssqlCustomDialer{
		executionId: execID,
		host:        "denied.host",
	}
	require.Equal(t, "denied.host", dialer.HostName())
	var _ gomssql.HostDialer = dialer

	_, err := dialer.DialContext(context.Background(), "tcp", "denied.host:1433")
	require.Error(t, err)
	require.Contains(t, err.Error(), "network policy")

	uninitDialer := &mssqlCustomDialer{
		executionId: "nonexistent-exec-id",
		host:        "example.com",
	}
	_, err = uninitDialer.DialContext(context.Background(), "tcp", "example.com:1433")
	require.Error(t, err)
	require.Contains(t, err.Error(), "dialers not initialized")
}

func TestConnectFailsFastOnClosedPort(t *testing.T) {
	execID := "mssql-closed-port-test"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, err := connect(ctx, execID, "127.0.0.1", port, "user", "pass", "master")
	require.Error(t, err)
	require.False(t, ok)
}

func TestConnectWithCanceledContext(t *testing.T) {
	execID := "mssql-canceled-ctx-test"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ok, err := connect(ctx, execID, "127.0.0.1", 1433, "user", "pass", "master")
	require.Error(t, err)
	require.False(t, ok)
}

func TestIsNetworkError(t *testing.T) {
	require.True(t, isNetworkError(errors.New("connect: connection refused")))
	require.True(t, isNetworkError(errors.New("No connection could be made because the target machine actively refused it.")))
	require.True(t, isNetworkError(errors.New("unable to open tcp connection with host '127.0.0.1:1433': cause=\"port closed or filtered\"")))
	require.True(t, isNetworkError(errors.New("network unreachable")))
	require.True(t, isNetworkError(errors.New("connection reset by peer")))
	require.True(t, isNetworkError(errors.New("i/o timeout")))
	require.True(t, isNetworkError(context.Canceled))
	require.True(t, isNetworkError(context.DeadlineExceeded))
	require.True(t, isNetworkError(protocolstate.ErrHostDenied.Msgf("127.0.0.1")))

	// Server-side responses / authentication failures are not network errors
	require.False(t, isNetworkError(nil))
	require.False(t, isNetworkError(errors.New("mssql: Login failed for user 'sa'")))
	require.False(t, isNetworkError(errors.New("mssql: Cannot open database \"secret\" requested by the login")))
	require.False(t, isNetworkError(errors.New("mssql: Password has expired")))
	require.False(t, isNetworkError(errors.New("mssql: Permission denied to database")))
	require.False(t, isNetworkError(errors.New("mssql: Password must be reset")))
	require.False(t, isNetworkError(errors.New("mssql: The query timed out")))
}

func TestExecuteQueryUsesFastdialer(t *testing.T) {
	execID := "mssql-execute-query-test"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	client := &MSSQLClient{}
	ctx := context.WithValue(context.Background(), "executionId", execID) //nolint:staticcheck // SA1029: executionId string key matches goja runtime injection

	// Denied host should fail policy check immediately
	_, err := client.ExecuteQuery(ctx, "denied.host", 1433, "user", "pass", "master", "SELECT 1")
	require.Error(t, err)

	// Closed port should fail
	_, err = client.ExecuteQuery(ctx, "127.0.0.1", 65530, "user", "pass", "master", "SELECT 1")
	require.Error(t, err)
}
