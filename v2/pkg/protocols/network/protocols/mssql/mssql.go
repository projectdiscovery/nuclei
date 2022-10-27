package mssql

import (
	"database/sql"
	"fmt"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/pkg/errors"
)

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	url := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;database=master;connection timeout=%d", host, port, username, password, timeout)

	db, err := sql.Open("mssql", url)
	if err != nil {
		return false, errors.Wrap(err, "could not connect to mssql")
	}
	defer func() {
		_ = db.Close()
	}()

	if err = db.Ping(); err != nil {
		return false, errors.Wrap(err, "could not ping mssql")
	}
	return true, nil
}
