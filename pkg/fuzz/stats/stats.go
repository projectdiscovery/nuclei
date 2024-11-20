// Package stats implements a statistics recording module for
// nuclei fuzzing.
package stats

import (
	"net/url"

	"github.com/pkg/errors"
)

// Tracker is a stats tracker module for fuzzing server
type Tracker struct {
	database StatsDatabase
}

// NewTracker creates a new tracker instance
func NewTracker(scanName string) (*Tracker, error) {
	db, err := newSqliteStatsDatabase(scanName)
	if err != nil {
		return nil, errors.Wrap(err, "could not create new tracker")
	}

	tracker := &Tracker{
		database: db,
	}
	return tracker, nil
}

// Close closes the tracker
func (t *Tracker) Close() {
	t.database.Close()
}

// FuzzingEvent is a fuzzing event
type FuzzingEvent struct {
	URL           string
	ComponentType string
	ComponentName string
	TemplateID    string
	PayloadSent   string
	StatusCode    int
	SiteName      string
}

func (t *Tracker) RecordEvent(event FuzzingEvent) {
	parsed, err := url.Parse(event.URL)
	if err != nil {
		return
	}

	// Site is the host:port combo
	event.SiteName = parsed.Host

	t.database.InsertRecord(event)
}
