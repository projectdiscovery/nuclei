package handlers

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/scans"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
)

// Server is a REST API handler server
type Server struct {
	db      *db.Database
	scans   *scans.ScanService
	targets *targets.TargetsStorage
}

// New returns a new rest api server handler instance
func New(db *db.Database, targets *targets.TargetsStorage, scans *scans.ScanService) *Server {
	return &Server{db: db, targets: targets, scans: scans}
}
