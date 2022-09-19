package disk

import (
	"io"
	"os"
)

// DiskCatalog is a template catalog helper implementation based on disk
type DiskCatalog struct {
	templatesDirectory string
}

// NewCatalog creates a new Catalog structure using provided input items
// using disk based items
func NewCatalog(directory string) *DiskCatalog {
	catalog := &DiskCatalog{templatesDirectory: directory}
	return catalog
}

// OpenFile opens a file and returns an io.ReadCloser to the file.
// It is used to read template and payload files based on catalog responses.
func (d *DiskCatalog) OpenFile(filename string) (io.ReadCloser, error) {
	file, err := os.Open(filename)
	return file, err
}
