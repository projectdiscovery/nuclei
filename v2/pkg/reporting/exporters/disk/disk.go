package disk

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/segmentio/ksuid"
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

	var filename string
	if outputFile := baseFilenameFromURL(event.Matched, event.Type); outputFile != "" {
		filename = outputFile
	} else {
		filename = ksuid.New().String()
	}

	filenameBuilder := &strings.Builder{}
	filenameBuilder.WriteString(filename)
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

// Taken from https://github.com/michenriksen/aquatone/blob/854a5d56fbb7a00b2e5ec80d443026c7a4ced798/core/session.go#L215
func baseFilenameFromURL(stru, protocol string) string {
	u, err := url.Parse(stru)
	if err != nil {
		return ""
	}

	h := sha1.New()
	_, _ = io.WriteString(h, u.Path)
	_, _ = io.WriteString(h, u.RawQuery)
	_, _ = io.WriteString(h, u.Fragment)

	pathHash := fmt.Sprintf("%x", h.Sum(nil))[0:16]
	host := strings.Replace(u.Host, ":", "__", 1)
	if u.Scheme == "" {
		u.Scheme = protocol
	}
	filename := fmt.Sprintf("%s__%s__%s", u.Scheme, strings.ReplaceAll(host, ".", "_"), pathHash)
	return strings.ToLower(filename)
}
