package jsonl

import (
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

type Exporter struct {
	options    *Options
	mutex      *sync.Mutex
	rows       []output.ResultEvent
	outputFile *os.File
}

// Options contains the configuration options for JSONL exporter client
type Options struct {
	// File is the file to export found JSONL result to
	File string `yaml:"file"`
	// OmitRaw whether to exclude the raw request and response from the output
	OmitRaw bool `yaml:"omit-raw"`
	// BatchSize the number of records to keep in memory before writing them out to the JSONL file or 0 to disable
	// batching (default)
	BatchSize int `yaml:"batch-size"`
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

// Export appends the passed result event to the list of objects to be exported to the resulting JSONL file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.options.OmitRaw {
		event.Request = ""
		event.Response = ""
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	// If the batch size is greater than 0 and the number of rows has reached the batch, flush it to the database
	if exporter.options.BatchSize > 0 && len(exporter.rows) >= exporter.options.BatchSize {
		err := exporter.WriteRows()
		if err != nil {
			// The error is already logged, return it to bubble up to the caller
			return err
		}
	}

	return nil
}

// WriteRows writes all rows from the rows list to JSONL file and removes them from the list
func (exporter *Exporter) WriteRows() error {
	// Open the file for writing if it's not already.
	// This will recreate the file if it exists, but keep the file handle so that batched writes within the same
	// execution are appended to the same file.
	var err error
	if exporter.outputFile == nil {
		// Open the JSONL file for writing and create it if it doesn't exist
		exporter.outputFile, err = os.OpenFile(exporter.options.File, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return errors.Wrap(err, "failed to create JSONL file")
		}
	}

	// Loop through the rows and write them, removing them as they're entered
	for len(exporter.rows) > 0 {
		row := exporter.rows[0]

		// Convert the row to JSON byte array and append a trailing newline. This is treated as a single line in JSONL
		obj, err := json.Marshal(row)
		if err != nil {
			return errors.Wrap(err, "failed to generate row for JSONL report")
		}

		obj = append(obj, '\n')

		// Attempt to append the JSON line to file specified in options.JSONLExport
		if _, err = exporter.outputFile.Write(obj); err != nil {
			return errors.Wrap(err, "failed to append JSONL line")
		}

		// Remove the item from the list
		exporter.rows = exporter.rows[1:]
	}

	return nil
}

// Close writes the in-memory data to the JSONL file specified by options.JSONLExport and closes the exporter after
// operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Write any remaining rows to the file
	// Write all pending rows
	err := exporter.WriteRows()
	if err != nil {
		// The error is already logged, return it to bubble up to the caller
		return err
	}

	// Close the file
	if err := exporter.outputFile.Close(); err != nil {
		return errors.Wrap(err, "failed to close JSONL file")
	}

	return nil
}
