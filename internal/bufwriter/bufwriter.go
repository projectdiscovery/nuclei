package bufwriter

import (
	"bufio"
	"os"
	"sync"
)

// Writer is a mutex protected buffered writer
type Writer struct {
	file   *os.File
	writer *bufio.Writer
	mutex  *sync.Mutex
}

// New creates a new mutex protected buffered writer for a file
func New(file string) (*Writer, error) {
	output, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &Writer{file: output, writer: bufio.NewWriter(output), mutex: &sync.Mutex{}}, nil
}

// Write writes a byte slice to the underlying file
//
// It also writes a newline if the last byte isn't a newline character.
func (w *Writer) Write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	_, err := w.writer.Write(data)
	if err != nil {
		return err
	}
	if data[len(data)-1] != '\n' {
		_, err = w.writer.WriteRune('\n')
	}
	return err
}

// WriteString writes a string to the underlying file
//
// It also writes a newline if the last byte isn't a newline character.
func (w *Writer) WriteString(data string) error {
	if data == "" {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	_, err := w.writer.WriteString(data)
	if err != nil {
		return err
	}
	if data[len(data)-1] != '\n' {
		_, err = w.writer.WriteRune('\n')
	}
	return err
}

// Close closes the underlying writer flushing everything to disk
func (w *Writer) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.writer.Flush()
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	return w.file.Close()
}
