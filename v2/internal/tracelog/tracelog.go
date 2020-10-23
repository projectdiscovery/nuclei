package tracelog

import (
	"os"
	"sync"

	jsoniter "github.com/json-iterator/go"
)

// Log is an interface for logging trace log of all the requests
type Log interface {
	// Close closes the log interface flushing data
	Close()
	// Request writes a log the requests trace log
	Request(templateID, url, requestType string, err error)
}

// NoopLogger is a noop logger that simply does nothing
type NoopLogger struct{}

// Close closes the log interface flushing data
func (n *NoopLogger) Close() {}

// Request writes a log the requests trace log
func (n *NoopLogger) Request(templateID, url, requestType string, err error) {}

// FileLogger is a trace logger that writes request logs to a file.
type FileLogger struct {
	encoder *jsoniter.Encoder
	file    *os.File
	mutex   *sync.Mutex
}

// NewFileLogger creates a new file logger structure
func NewFileLogger(path string) (*FileLogger, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &FileLogger{file: file, encoder: jsoniter.NewEncoder(file), mutex: &sync.Mutex{}}, nil
}

// Close closes the log interface flushing data
func (f *FileLogger) Close() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.file.Close()
}

// JSONRequest is a trace log request written to file
type JSONRequest struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Error string `json:"error"`
	Type  string `json:"type"`
}

// Request writes a log the requests trace log
func (f *FileLogger) Request(templateID, url, requestType string, err error) {
	request := &JSONRequest{
		ID:   templateID,
		URL:  url,
		Type: requestType,
	}
	if err != nil {
		request.Error = err.Error()
	} else {
		request.Error = "none"
	}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	//nolint:errcheck // We don't need to do anything here
	f.encoder.Encode(request)
}
