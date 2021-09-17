package output

import (
	"os"
)

// fileWriter is a concurrent file based output writer.
type fileWriter struct {
	file *os.File
}

// NewFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output}, nil
}

// WriteString writes an output to the underlying file
func (w *fileWriter) Write(data []byte) error {
	if _, err := w.file.Write(data); err != nil {
		return err
	}
	_, err := w.file.Write([]byte("\n"))
	return err
}

// Close closes the underlying writer flushing everything to disk
func (w *fileWriter) Close() error {
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	return w.file.Close()
}
