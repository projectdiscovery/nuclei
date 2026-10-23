package output

import (
	"os"
	"sync"
)

// fileWriter is a concurrent file based output writer.
type fileWriter struct {
	file *os.File
	mu   sync.Mutex
}

// NewFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string, resume bool) (*fileWriter, error) {
	var output *os.File
	var err error
	if resume {
		output, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		output, err = os.Create(file)
	}
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output}, nil
}

// WriteString writes an output to the underlying file
func (w *fileWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.file.Write(data); err != nil {
		return 0, err
	}
	if _, err := w.file.Write([]byte("\n")); err != nil {
		return 0, err
	}
	return len(data) + 1, nil
}

// Close closes the underlying writer flushing everything to disk
func (w *fileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	return w.file.Close()
}
