package markdown

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
)

type Exporter struct {
	directory string
	options   *Options
}

// Options contains the configuration options for GitHub issue tracker client
type Options struct {
	// Directory is the directory to export found results to
	Directory string `yaml:"directory"`
}

// New creates a new markdown exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	directory := options.Directory
	if options.Directory == "" {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		directory = dir
	}
	_ = os.MkdirAll(directory, 0755)
	return &Exporter{options: options, directory: directory}, nil
}

// Export exports a passed result event to markdown
func (i *Exporter) Export(event *output.ResultEvent) error {
	summary := format.Summary(event)
	description := format.MarkdownDescription(event)

	filenameBuilder := &strings.Builder{}
	filenameBuilder.WriteString(event.TemplateID)
	filenameBuilder.WriteString("-")
	filenameBuilder.WriteString(strings.ReplaceAll(strings.ReplaceAll(event.Matched, "/", "_"), ":", "_"))

	var suffix string
	if event.MatcherName != "" {
		suffix = event.MatcherName
	} else if event.ExtractorName != "" {
		suffix = event.ExtractorName
	}
	if suffix != "" {
		filenameBuilder.WriteRune('-')
		filenameBuilder.WriteString(event.MatcherName)
	}
	filenameBuilder.WriteString(".md")
	finalFilename := sanitizeFilename(filenameBuilder.String())

	dataBuilder := &bytes.Buffer{}
	dataBuilder.WriteString("### ")
	dataBuilder.WriteString(summary)
	dataBuilder.WriteString("\n---\n")
	dataBuilder.WriteString(description)
	data := dataBuilder.Bytes()

	return ioutil.WriteFile(filepath.Join(i.directory, finalFilename), data, 0644)
}

// Close closes the exporter after operation
func (i *Exporter) Close() error {
	return nil
}

func sanitizeFilename(filename string) string {
	if len(filename) > 256 {
		filename = filename[0:255]
	}
	return filename
}
