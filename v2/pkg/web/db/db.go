//go:generate sqlc generate
//go:generate mockgen -source=dbsql/querier.go -destination=mock_db.go -package=db
package db

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// Database is a database access layer for nuclei rest api
type Database struct {
	pool *pgxpool.Pool
}

// New returns a new database object from configuration
func New(postgresURL string) (*Database, error) {
	pool, err := pgxpool.Connect(context.Background(), postgresURL)
	if err != nil {
		return nil, err
	}
	return &Database{pool: pool}, nil
}

// Queries returns the dbsql queries structure
func (d *Database) Queries() dbsql.Querier {
	return dbsql.New(d.pool)
}

// Close closes the database connection pool
func (d *Database) Close() {
	d.pool.Close()
}
