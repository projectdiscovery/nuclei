package jsonexporter

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"os"
	"sync"
)

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []output.ResultEvent
}

// Options contains the configuration options for JSON exporter client
type Options struct {
	// File is the file to export found JSON result to
	File              string `yaml:"file"`
	IncludeRawPayload bool   `yaml:"include-raw-payload"`
}

// New creates a new JSON exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
// the resulting JSON file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// If the IncludeRawPayload is not set, then set the request and response to an empty string in the event to avoid
	// writing them to the list of events.
	// This will reduce the amount of storage as well as the fields being excluded from the resulting JSON output since
	// the property is set to "omitempty"
	if !exporter.options.IncludeRawPayload {
		event.Request = ""
		event.Response = ""
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	return nil
}

// Close writes the in-memory data to the JSON file specified by options.JSONExport
// and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Convert the rows to JSON byte array
	obj, err := json.Marshal(exporter.rows)
	if err != nil {
		return errors.Wrap(err, "failed to generate JSON report")
	}

	// Attempt to write the JSON to file specified in options.JSONExport
	if err := os.WriteFile(exporter.options.File, obj, 0644); err != nil {
		return errors.Wrap(err, "failed to create JSON file")
	}

	return nil
}
