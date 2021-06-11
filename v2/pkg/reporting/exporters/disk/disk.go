package disk

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
)

type Exporter struct {
	directory string
	options   *Options
}

// Options contains the configuration options for github issue tracker client
type Options struct {
	// Directory is the directory to export found results to
	Directory string `yaml:"directory"`
}

// New creates a new disk exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	directory := options.Directory
	if options.Directory == "" {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		directory = dir
	}
	_ = os.MkdirAll(directory, os.ModePerm)
	return &Exporter{options: options, directory: directory}, nil
}

// Export exports a passed result event to disk
func (i *Exporter) Export(event *output.ResultEvent) error {
	summary := format.Summary(event)
	description := format.MarkdownDescription(event)

	filenameBuilder := &strings.Builder{}
	filenameBuilder.WriteString(event.TemplateID)
	filenameBuilder.WriteString("-")
	filenameBuilder.WriteString(strings.ReplaceAll(strings.ReplaceAll(event.Matched, "/", "_"), ":", "_"))
	filenameBuilder.WriteString(".md")
	finalFilename := filenameBuilder.String()

	dataBuilder := &bytes.Buffer{}
	dataBuilder.WriteString("### ")
	dataBuilder.WriteString(summary)
	dataBuilder.WriteString("\n---\n")
	dataBuilder.WriteString(description)
	data := dataBuilder.Bytes()

	err := ioutil.WriteFile(path.Join(i.directory, finalFilename), data, 0644)
	return err
}

// Close closes the exporter after operation
func (i *Exporter) Close() error {
	return nil
}
