package output

import (
	"io"
	"os"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	fileutil "github.com/projectdiscovery/utils/file"
)

// WriterOptions contains configuration options for a writer
type WriterOptions func(s *StandardWriter) error

// WithJson writes output in json format
func WithJson(json bool, dumpReqResp bool) WriterOptions {
	return func(s *StandardWriter) error {
		s.json = json
		s.jsonReqResp = dumpReqResp
		return nil
	}
}

// WithTimestamp writes output with timestamp
func WithTimestamp(timestamp bool) WriterOptions {
	return func(s *StandardWriter) error {
		s.timestamp = timestamp
		return nil
	}
}

// WithNoMetadata disables metadata output
func WithNoMetadata(noMetadata bool) WriterOptions {
	return func(s *StandardWriter) error {
		s.noMetadata = noMetadata
		return nil
	}
}

// WithMatcherStatus writes output with matcher status
func WithMatcherStatus(matcherStatus bool) WriterOptions {
	return func(s *StandardWriter) error {
		s.matcherStatus = matcherStatus
		return nil
	}
}

// WithAurora sets the aurora instance for the writer
func WithAurora(aurora aurora.Aurora) WriterOptions {
	return func(s *StandardWriter) error {
		s.aurora = aurora
		return nil
	}
}

// WithWriter sets the writer for the writer
func WithWriter(outputFile io.WriteCloser) WriterOptions {
	return func(s *StandardWriter) error {
		s.outputFile = outputFile
		return nil
	}
}

// WithTraceSink sets the writer where trace output is written
func WithTraceSink(traceFile io.WriteCloser) WriterOptions {
	return func(s *StandardWriter) error {
		s.traceFile = traceFile
		return nil
	}
}

// WithErrorSink sets the writer where error output is written
func WithErrorSink(errorFile io.WriteCloser) WriterOptions {
	return func(s *StandardWriter) error {
		s.errorFile = errorFile
		return nil
	}
}

// WithSeverityColors sets the color function for severity
func WithSeverityColors(severityColors func(severity.Severity) string) WriterOptions {
	return func(s *StandardWriter) error {
		s.severityColors = severityColors
		return nil
	}
}

// WithStoreResponse sets the store response option
func WithStoreResponse(storeResponse bool, respDir string) WriterOptions {
	return func(s *StandardWriter) error {
		s.storeResponse = storeResponse
		s.storeResponseDir = respDir
		return nil
	}
}

// NewWriter creates a new output writer
// if no writer is specified it writes to stdout
func NewWriter(opts ...WriterOptions) (*StandardWriter, error) {
	s := &StandardWriter{
		mutex:                 &sync.Mutex{},
		DisableStdout:         true,
		AddNewLinesOutputFile: true,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.aurora == nil {
		s.aurora = aurora.NewAurora(false)
	}
	if s.outputFile == nil {
		s.outputFile = os.Stdout
	}
	// Try to create output folder if it doesn't exist
	if s.storeResponse && !fileutil.FolderExists(s.storeResponseDir) {
		if err := fileutil.CreateFolder(s.storeResponseDir); err != nil {
			return nil, err
		}
	}
	return s, nil
}
