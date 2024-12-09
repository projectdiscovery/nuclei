package stats

import (
	_ "embed"

	_ "github.com/mattn/go-sqlite3"
)

type StatsDatabase interface {
	Close()

	InsertComponent(event ComponentEvent) error
	InsertMatchedRecord(event FuzzingEvent) error
	InsertError(event ErrorEvent) error
}
