package utils

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var errRowsBroken = errors.New("connection reset mid-result")

// brokenRowsDriver returns one row and then fails, like a result set cut off
// by a dropped connection.
type brokenRowsDriver struct{}

type brokenRowsConn struct{}

type brokenRowsStmt struct{}

type brokenRows struct{ sent bool }

func (brokenRowsDriver) Open(string) (driver.Conn, error) { return brokenRowsConn{}, nil }

func (brokenRowsConn) Prepare(string) (driver.Stmt, error) { return brokenRowsStmt{}, nil }
func (brokenRowsConn) Close() error                        { return nil }
func (brokenRowsConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (brokenRowsStmt) Close() error  { return nil }
func (brokenRowsStmt) NumInput() int { return -1 }
func (brokenRowsStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("not supported")
}
func (brokenRowsStmt) Query([]driver.Value) (driver.Rows, error) { return &brokenRows{}, nil }

func (*brokenRows) Columns() []string { return []string{"name"} }
func (*brokenRows) Close() error      { return nil }
func (r *brokenRows) Next(dest []driver.Value) error {
	if r.sent {
		return errRowsBroken
	}
	r.sent = true
	dest[0] = "first"
	return nil
}

func init() {
	sql.Register("nuclei-test-broken-rows", brokenRowsDriver{})
}

func TestUnmarshalSQLRowsReportsIterationError(t *testing.T) {
	db, err := sql.Open("nuclei-test-broken-rows", "")
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query("SELECT name")
	require.NoError(t, err)

	result, err := UnmarshalSQLRows(rows)
	require.ErrorIs(t, err, errRowsBroken)
	require.NotNil(t, result)
	require.Len(t, result.Rows, 1, "rows read before the error are still returned")
	require.Equal(t, map[string]interface{}{"name": "first"}, result.Rows[0])
}
