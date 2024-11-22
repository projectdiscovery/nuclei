// Package stats implements a statistics recording module for
// nuclei fuzzing.
package stats

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// Tracker is a stats tracker module for fuzzing server
type Tracker struct {
	database StatsDatabase
}

// NewTracker creates a new tracker instance
func NewTracker(scanName string) (*Tracker, error) {
	db, err := NewSqliteStatsDatabase(scanName)
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
	_, err := t.database.(*sqliteStatsDatabase).db.Exec("VACUUM")
	if err != nil {
		gologger.Error().Msgf("could not truncate wal: %s", err)
	}

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
	Matched       bool
	SiteName      string
	RawRequest    string
	RawResponse   string
}

func (t *Tracker) RecordResultEvent(event FuzzingEvent) {
	event.SiteName = getCorrectSiteName(event.URL)
	t.database.InsertMatchedRecord(event)
}

func (t *Tracker) RecordComponentEvent(event FuzzingEvent) {
	event.SiteName = getCorrectSiteName(event.URL)
	t.database.InsertComponent(event)
}

func getCorrectSiteName(originalURL string) string {
	parsed, err := url.Parse(originalURL)
	if err != nil {
		return ""
	}

	// Site is the host:port combo
	siteName := parsed.Host
	if parsed.Port() == "" {
		if parsed.Scheme == "https" {
			siteName = fmt.Sprintf("%s:443", siteName)
		} else if parsed.Scheme == "http" {
			siteName = fmt.Sprintf("%s:80", siteName)
		}
	}
	return siteName
}
