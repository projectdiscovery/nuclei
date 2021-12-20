package handlers

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// Server is a REST API handler server
type Server struct {
	db      dbsql.Querier
	scans   *scans.ScanService
	targets *targets.TargetsStorage
}

// New returns a new rest api server handler instance
func New(db dbsql.Querier, targets *targets.TargetsStorage, scans *scans.ScanService) *Server {
	return &Server{db: db, targets: targets, scans: scans}
}
