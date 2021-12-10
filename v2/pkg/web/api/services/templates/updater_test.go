package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	database, err := db.New("postgres://postgres:mysecretpassword@localhost:5432/postgres")
	require.Nil(t, err, "could not connect to db")
	defer database.Close()

	close := RunUpdateChecker(database)
	close()
}
