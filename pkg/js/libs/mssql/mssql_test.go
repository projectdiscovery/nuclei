package mssql

import (
	"testing"

	"github.com/microsoft/go-mssqldb/msdsn"
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
