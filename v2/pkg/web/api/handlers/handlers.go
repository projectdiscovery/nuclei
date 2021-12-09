package handlers

import "github.com/projectdiscovery/nuclei/v2/pkg/web/db"

// Server is a REST API handler server
type Server struct {
	db *db.Database
}

// New returns a new rest api server handler instance
func New(db *db.Database) *Server {
	return &Server{db: db}
}
