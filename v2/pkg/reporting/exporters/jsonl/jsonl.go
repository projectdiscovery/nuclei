package jsonl

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

// Options contains the configuration options for JSONL exporter client
type Options struct {
	// File is the file to export found JSONL result to
	File              string `yaml:"file"`
	IncludeRawPayload bool   `yaml:"include-raw-payload"`
}

// New creates a new JSONL exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
// the resulting JSONL file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// If the IncludeRawPayload is not set, then set the request and response to an empty string in the event to avoid
	// writing them to the list of events.
	// This will reduce the amount of storage as well as the fields being excluded from the resulting JSONL output since
	// the property is set to "omitempty"
	if !exporter.options.IncludeRawPayload {
		event.Request = ""
		event.Response = ""
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	return nil
}

// Close writes the in-memory data to the JSONL file specified by options.JSONLExport
// and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Open the JSONL file for writing and create it if it doesn't exist
	f, err := os.OpenFile(exporter.options.File, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to create JSONL file")
	}

	// Loop through the rows and convert each to a JSON byte array and write to file
	for _, row := range exporter.rows {
		// Convert the row to JSON byte array and append a trailing newline. This is treated as a single line in JSONL
		obj, err := json.Marshal(row)
		if err != nil {
			return errors.Wrap(err, "failed to generate row for JSONL report")
		}

		// Add a trailing newline to the JSON byte array to confirm with the JSONL format
		obj = append(obj, '\n')

		// Attempt to append the JSON line to file specified in options.JSONLExport
		if _, err = f.Write(obj); err != nil {
			return errors.Wrap(err, "failed to append JSONL line")
		}
	}

	// Close the file
	if err := f.Close(); err != nil {
		return errors.Wrap(err, "failed to close JSONL file")
	}

	return nil
}
