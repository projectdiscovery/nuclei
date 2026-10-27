package protocolstate

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// SanitizeMySQLDSN enforces filesystem sandbox rules on a MySQL DSN. It always
// removes allowAllFiles: that option lets the server read any client file
// through LOAD DATA LOCAL INFILE, and -lfa must never disable the allowlist.
// RegisterMySQLLocalInfiles allows single allowlisted files instead.
func SanitizeMySQLDSN(dsn string, options *types.Options) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	cfg.AllowAllFiles = false
	return cfg.FormatDSN(), nil
}

// mysqlLocalInfilePattern finds the file literal of LOAD DATA/XML LOCAL INFILE.
var mysqlLocalInfilePattern = regexp.MustCompile(`(?is)\bLOAD\s+(?:DATA|XML)\s+(?:(?:LOW_PRIORITY|CONCURRENT)\s+)?LOCAL\s+INFILE\s+(?:'((?:[^'\\]|\\.|'')*)'|"((?:[^"\\]|\\.|"")*)")`)

var (
	mysqlLocalFilesMu sync.Mutex
	mysqlLocalFiles   = map[string]int{}
	// registerMySQLLocalFile and deregisterMySQLLocalFile are the mysql
	// driver's process-wide file registry, replaceable in tests.
	registerMySQLLocalFile   = mysql.RegisterLocalFile
	deregisterMySQLLocalFile = mysql.DeregisterLocalFile
)

// RegisterMySQLLocalInfiles allows LOAD DATA LOCAL INFILE for the files that
// query names. It does so only when the DSN asks for local files
// (allowAllFiles=true), -lfa is enabled, and every file is an absolute path
// inside the filesystem allowlist; a file outside it is an error. Each file
// is registered with the mysql driver by its exact path, so the server can
// only request registered (allowlisted) files, never an arbitrary one. The
// caller must call the returned release func after the query.
func RegisterMySQLLocalInfiles(options *types.Options, dsn, query string) (func(), error) {
	noop := func() {}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return noop, err
	}
	if !cfg.AllowAllFiles || options == nil || !IsLfaAllowed(options) {
		return noop, nil
	}
	var files []string
	for _, match := range mysqlLocalInfilePattern.FindAllStringSubmatch(query, -1) {
		path := unescapeMySQLString(match[1])
		if match[1] == "" {
			path = unescapeMySQLString(match[2])
		}
		if !filepath.IsAbs(path) {
			return noop, fmt.Errorf("%w: LOAD DATA LOCAL INFILE path %q must be absolute", ErrPathDenied, path)
		}
		if _, err := NormalizePath(options, path); err != nil {
			return noop, err
		}
		files = append(files, path)
	}
	if len(files) == 0 {
		return noop, nil
	}
	mysqlLocalFilesMu.Lock()
	for _, file := range files {
		if mysqlLocalFiles[file] == 0 {
			registerMySQLLocalFile(file)
		}
		mysqlLocalFiles[file]++
	}
	mysqlLocalFilesMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			mysqlLocalFilesMu.Lock()
			defer mysqlLocalFilesMu.Unlock()
			for _, file := range files {
				mysqlLocalFiles[file]--
				if mysqlLocalFiles[file] <= 0 {
					delete(mysqlLocalFiles, file)
					deregisterMySQLLocalFile(file)
				}
			}
		})
	}, nil
}

// unescapeMySQLString decodes the backslash and doubled-quote escapes of a
// MySQL string literal body.
func unescapeMySQLString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if (c == '\'' || c == '"') && i+1 < len(s) && s[i+1] == c {
			i++
		}
		b.WriteByte(c)
	}
	return b.String()
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
