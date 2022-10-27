package mysql

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
)

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	url := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8&timeout=%ds", username, password, host, port, "mysql", timeout)
	db, err := sql.Open("mysql", url)
	if err != nil {
		return false, errors.Wrap(err, "could not connect to mysql")
	}
	defer func() {
		_ = db.Close()
	}()

	if err = db.Ping(); err != nil {
		return false, errors.Wrap(err, "could not ping mysql")
	}
	return true, nil
}
