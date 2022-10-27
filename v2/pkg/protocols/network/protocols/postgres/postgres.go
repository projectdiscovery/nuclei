package postgres

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
)

// ConnectWithCredentials connects to a server with credentials
func ConnectWithCredentials(host, username, password string, port, timeout int) (bool, error) {
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=%ds", username, password, host, port, "postgres", timeout)

	db, err := sql.Open("postgres", url)
	if err != nil {
		return false, errors.Wrap(err, "could not connect to postgres")
	}
	defer func() {
		_ = db.Close()
	}()

	if err = db.Ping(); err != nil {
		return false, errors.Wrap(err, "could not ping postgres")
	}
	return true, nil
}
