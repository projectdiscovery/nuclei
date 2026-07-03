package protocolstate

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// SanitizeMySQLDSN enforces filesystem sandbox rules on a MySQL DSN.
func SanitizeMySQLDSN(dsn string, options *types.Options) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	lfaAllowed := options != nil && IsLfaAllowed(options)
	if cfg.AllowAllFiles && !lfaAllowed {
		cfg.AllowAllFiles = false
	}
	return cfg.FormatDSN(), nil
}

// SanitizeOracleDSN normalizes oracle trace-related DSN options through the
// filesystem allowlist broker.
func SanitizeOracleDSN(executionID, dsn string, options *types.Options) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	if options == nil {
		options = &types.Options{ExecutionId: executionID}
	}
	query := parsed.Query()
	changed := false
	for key, values := range query {
		if !isOracleTracePathOption(key) {
			continue
		}
		for i, value := range values {
			if value == "" {
				continue
			}
			normalized, err := NormalizePath(options, value)
			if err != nil {
				return "", fmt.Errorf("oracle %s %q: %w", key, value, err)
			}
			values[i] = normalized
		}
		query[key] = values
		changed = true
	}
	if !changed {
		return dsn, nil
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func isOracleTracePathOption(key string) bool {
	switch strings.ToUpper(strings.TrimSpace(key)) {
	case "TRACE FILE", "TRACE DIR", "TRACE FOLDER", "TRACE DIRECTORY":
		return true
	default:
		return false
	}
}

// SanitizeMSSQLDatabaseName escapes database names used in MSSQL connection strings.
func SanitizeMSSQLDatabaseName(dbName string) string {
	return url.QueryEscape(dbName)
}

// SanitizePostgresDatabaseName escapes database names used in postgres URLs.
func SanitizePostgresDatabaseName(dbName string) string {
	return url.PathEscape(dbName)
}
