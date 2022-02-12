package targets

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// TargetsStorage stores targets in UUID format in a directory
type TargetsStorage struct {
	directory string
}

// NewTargetsStorage returns a new target storage from directory
func NewTargetsStorage(directory string) *TargetsStorage {
	return &TargetsStorage{directory: directory}
}

// Create stores data from an io.Reader and returns UUID for it
func (t *TargetsStorage) Create() (io.WriteCloser, string, error) {
	id := uuid.New().String()

	targetPath := filepath.Join(t.directory, id)
	file, err := os.Create(targetPath)
	return file, id, err
}

// Update takes an ID and returns an io.Writer in update mode
func (t *TargetsStorage) Update(id string) (io.WriteCloser, error) {
	targetPath := filepath.Join(t.directory, id)
	file, err := os.OpenFile(targetPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return file, err
}

// Read takes an ID and returns an io.Reader
func (t *TargetsStorage) Read(id string) (io.ReadCloser, error) {
	targetPath := filepath.Join(t.directory, id)
	file, err := os.Open(targetPath)
	return file, err
}

// Read takes an ID and returns an io.Reader
func (t *TargetsStorage) Delete(id string) error {
	targetPath := filepath.Join(t.directory, id)
	err := os.Remove(targetPath)
	return err
}

// NewLineCountWriter counts newlines and implements io.Writer
type NewLineCountWriter struct {
	Total int64
}

// Write counts newline implementing io.Writer interface
func (n *NewLineCountWriter) Write(p []byte) (int, error) {
	n.Total += int64(bytes.Count(p, []byte("\n")))
	if !bytes.HasSuffix(p, []byte("\n")) {
		n.Total += 1
	}
	return len(p), nil
}
