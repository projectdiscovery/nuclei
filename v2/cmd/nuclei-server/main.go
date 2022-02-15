package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/handlers"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/services/updater"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var (
	datadir = flag.String("data-dir", "data", "Data directory for nuclei server")
	logsdir = flag.String("logs-dir", "logs", "Logs directory for nuclei server")
	json    = flag.Bool("json", false, "show json logs")

	token = flag.String("token", "", "Token for nuclei REST API")
	host  = flag.String("host", "localhost", "Host to listen REST API on")
	port  = flag.Int("port", 8822, "Port to listen REST API on")
	dburl = flag.String("db-url", "postgres://postgres:mysecretpassword@localhost:5432/postgres", "database connection url for postgres db")
)

func main() {
	flag.Parse()

	if *json {
		gologger.DefaultLogger.SetFormatter(&formatter.JSON{})
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	_ = protocolinit.Init(testutils.DefaultOptions)

	if err := process(); err != nil {
		gologger.Fatal().Msgf("Could not run server: %s\n", err)
	}
}

func process() error {
	database, err := db.New(*dburl)
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

	if *datadir == "" {
		cwd, _ := os.Getwd()
		_ = os.MkdirAll(path.Join(cwd, *datadir), os.ModePerm)
		_ = os.MkdirAll(path.Join(cwd, *logsdir), os.ModePerm)
	} else {
		_ = os.Mkdir(*datadir, os.ModePerm)
		_ = os.Mkdir(*logsdir, os.ModePerm)
	}

	targets := targets.NewTargetsStorage(*datadir)
	scans := scans.NewScanService(*logsdir, false, 1, dbInstance, targets)
	defer scans.Close()

	server := handlers.New(dbInstance, targets, scans)

	authToken := *token
	if authToken == "" {
		authToken = uuid.NewString()
	}
	gologger.Info().Msgf("Using authentication token: %s", authToken)

	api := api.New(&api.Config{
		Token:  authToken,
		Host:   *host,
		Port:   *port,
		TLS:    false,
		Server: server,
	})
	gologger.Info().Msgf("Listening on %s:%d", *host, *port)
	return http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), api.Echo())
}
