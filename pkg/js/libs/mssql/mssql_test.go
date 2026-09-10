package mssql

import (
	"context"
	"strings"
	"testing"

	"github.com/microsoft/go-mssqldb/msdsn"
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

	cfg, err := msdsn.Parse(mssqlConnString("127.0.0.1:1433", MSSQLOptions{
		Username: "user", Password: "password", DbName: dbName,
	}))
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

func TestConnectWithOptionsValidatesTarget(t *testing.T) {
	connected, err := connectWithOptions(context.Background(), "test", MSSQLOptions{Port: 1433})
	require.False(t, connected)
	require.EqualError(t, err, "invalid host or port")
}

func TestConnectWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	connected, err := connectWithOptions(context.Background(), executionID, MSSQLOptions{
		Host: "127.0.0.1", Port: 1433,
	})
	require.False(t, connected)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "network policy") && strings.Contains(err.Error(), "127.0.0.1"))
}

func TestConnectionStringKeepsPlainDatabaseName(t *testing.T) {
	cfg, err := msdsn.Parse(mssqlConnString("127.0.0.1:1433", MSSQLOptions{
		Username: "user", Password: "password", DbName: "master", Timeout: 12,
	}))
	require.NoError(t, err)

	require.Equal(t, "master", cfg.Database)
	require.Equal(t, "12", cfg.Parameters["connection timeout"])
}
