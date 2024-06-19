package disk

import (
	"io"
	"io/fs"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// DiskCatalog is a template catalog helper implementation based on disk
type DiskCatalog struct {
	templatesDirectory string
	templatesFS        fs.FS
	customTemplatesFS  bool // This will be true if the user gave us a templatesFS
}

// NewCatalog creates a new Catalog structure using provided input items
// using disk based items
func NewCatalog(directory string) *DiskCatalog {
	catalog := &DiskCatalog{templatesDirectory: directory}
	if directory != "" {
		wd, _ := os.Getwd()
		catalog.templatesFS = os.DirFS(wd)
		catalog.templatesDirectory = ""
	} else {
		catalog.templatesFS = os.DirFS(config.DefaultConfig.GetTemplateDir())
	}
	return catalog
}

// NewFSCatalog creates a new Catalog structure using provided input items
// using the fs.FS as its filesystem.
func NewFSCatalog(fs fs.FS, directory string) *DiskCatalog {
	catalog := &DiskCatalog{
		templatesDirectory: directory,
		templatesFS:        fs,
		customTemplatesFS:  true,
	}
	return catalog
}

// OpenFile opens a file and returns an io.ReadCloser to the file.
// It is used to read template and payload files based on catalog responses.
func (d *DiskCatalog) OpenFile(filename string) (io.ReadCloser, error) {
	gologger.Debug().Msgf("DiskCatalog: OpenFile: %s", filename)

	return d.templatesFS.Open(filename)
}
