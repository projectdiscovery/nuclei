package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestAPI(t *testing.T) {
	//	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	_ = protocolinit.Init(testutils.DefaultOptions)

	database, err := db.New("postgres://postgres:mysecretpassword@localhost:5432/postgres")
	require.Nil(t, err, "could not connect to db")
	defer database.Close()

	err = settings.InitializeDefaultSettings(database)
	require.Nil(t, err, "could not init settings to db")

	tempdir, err := ioutil.TempDir("", "test")
	require.Nil(t, err, "could not create tempdir")
	defer os.RemoveAll(tempdir)

	logsDir, err := ioutil.TempDir("", "logs")
	require.Nil(t, err, "could not create tempdir")
	defer os.RemoveAll(logsDir)

	dbInstance := database.Queries()

	targets := targets.NewTargetsStorage(tempdir)
	scans := scans.NewScanService(logsDir, false, 1, dbInstance, targets)
	defer scans.Close()

	server := handlers.New(dbInstance, targets, scans)

	api := New(&Config{
		Userame:  "user",
		Password: "pass",
		Host:     "localhost",
		Port:     8822,
		TLS:      false,
		Server:   server,
	})
	_ = http.ListenAndServe(fmt.Sprintf("%s:%d", "localhost", 8822), api.echo)
}
