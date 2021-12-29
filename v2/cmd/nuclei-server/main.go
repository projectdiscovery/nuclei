package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/updater"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
)

var (
	datadir = flag.String("data-dir", "data", "Data directory for nuclei server")
	logsdir = flag.String("logs-dir", "logs", "Logs directory for nuclei server")

	username = flag.String("user", "user", "Username for nuclei REST API")
	password = flag.String("password", "pass", "Password for nuclei REST API")
	host     = flag.String("host", "localhost", "Host to listen REST API on")
	port     = flag.Int("port", 8822, "Port to listen REST API on")
)

func main() {
	flag.Parse()

	_ = os.Mkdir(*datadir, 0600)
	_ = os.Mkdir(*logsdir, 0600)

	//	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	_ = protocolinit.Init(testutils.DefaultOptions)

	if err := process(); err != nil {
		gologger.Fatal().Msgf("Could not run server: %s\n", err)
	}
}

func process() error {
	database, err := db.New("postgres://postgres:mysecretpassword@localhost:5432/postgres")
	if err != nil {
		return errors.Wrap(err, "could not connect to db")
	}
	defer database.Close()

	close := updater.RunUpdateChecker(database)
	defer close()

	err = database.Migrate()
	if err != nil {
		return errors.Wrap(err, "could not migrate db")
	}

	err = settings.InitializeDefaultSettings(database)
	if err != nil {
		return errors.Wrap(err, "could not init default settings")
	}

	dbInstance := database.Queries()

	targets := targets.NewTargetsStorage(*datadir)
	scans := scans.NewScanService(*logsdir, 1, dbInstance, targets)
	defer scans.Close()

	server := handlers.New(dbInstance, targets, scans)

	api := api.New(&api.Config{
		Userame:  *username,
		Password: *password,
		Host:     *host,
		Port:     *port,
		TLS:      false,
		Server:   server,
	})
	gologger.Info().Msgf("Listening on %s:%d", *host, *port)
	return http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), api.Echo())
}
