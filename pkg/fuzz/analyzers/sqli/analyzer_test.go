package sqli

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("sqli_error"))
	require.Equal(t, "sqli_error", (&Analyzer{}).Name())
}

func TestMatchDBMSError(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantDBMS string
		wantHit  bool
	}{
		{
			name:     "mysql syntax error",
			body:     `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''`,
			wantDBMS: "MySQL",
			wantHit:  true,
		},
		{
			name:     "postgres error",
			body:     `Query failed: ERROR: unterminated quoted string at or near "'"`,
			wantDBMS: "PostgreSQL",
			wantHit:  true,
		},
		{
			name:     "mssql unclosed quotation",
			body:     `Unclosed quotation mark after the character string ''.`,
			wantDBMS: "Microsoft SQL Server",
			wantHit:  true,
		},
		{
			name:     "oracle ORA code",
			body:     `ORA-01756: quoted string not properly terminated`,
			wantDBMS: "Oracle",
			wantHit:  true,
		},
		{
			name:     "sqlite operational error",
			body:     `sqlite3.OperationalError: unrecognized token: "'"`,
			wantDBMS: "SQLite",
			wantHit:  true,
		},
		{
			name:    "benign html no error",
			body:    `<html><body><h1>Welcome</h1><p>no errors here</p></body></html>`,
			wantHit: false,
		},
		{
			name:    "the word mysql alone is not a match",
			body:    `We use MySQL as our database backend. Learn more in the docs.`,
			wantHit: false,
		},
		{
			name:    "empty body",
			body:    ``,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbms, hit := MatchDBMSError(tc.body)
			require.Equal(t, tc.wantHit, hit)
			if tc.wantHit {
				require.Equal(t, tc.wantDBMS, dbms)
			}
		})
	}
}

func TestBreakingPayloadsNonEmpty(t *testing.T) {
	require.NotEmpty(t, breakingPayloads)
	for _, p := range breakingPayloads {
		require.NotEmpty(t, p)
	}
}
