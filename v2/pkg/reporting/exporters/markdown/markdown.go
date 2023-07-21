package markdown

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

const indexFileName = "index.md"
const extension = ".md"

type Exporter struct {
	directory string
	options   *Options
}

// Options contains the configuration options for GitHub issue tracker client
type Options struct {
	// Directory is the directory to export found results to
	Directory         string `yaml:"directory"`
	IncludeRawPayload bool   `yaml:"include-raw-payload"`
	SortMode          string `yaml:"sort-mode"`
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

	// index generation header
	dataHeader := util.CreateTableHeader("Hostname/IP", "Finding", "Severity")

	err := os.WriteFile(filepath.Join(directory, indexFileName), []byte(dataHeader), 0644)
	if err != nil {
		return nil, err
	}

	return &Exporter{options: options, directory: directory}, nil
}

// Export exports a passed result event to markdown
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	// If the IncludeRawPayload is not set, then set the request and response to an empty string in the event to avoid
	// writing them to the list of events.
	// This will reduce the amount of storage as well as the fields being excluded from the markdown report output since
	// the property is set to "omitempty"
	if !exporter.options.IncludeRawPayload {
		event.Request = ""
		event.Response = ""
	}

	// index file generation
	file, err := os.OpenFile(filepath.Join(exporter.directory, indexFileName), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	filename := createFileName(event)

	// If the sort mode is set to severity, host, or template, then we need to get a safe version of the name for a
	// subdirectory to store the file in.
	// This will allow us to sort the files into subdirectories based on the sort mode. The subdirectory will need to
	// be created if it does not exist.
	fileUrl := filename
	subdirectory := ""
	switch exporter.options.SortMode {
	case "severity":
		subdirectory = event.Info.SeverityHolder.Severity.String()
	case "host":
		subdirectory = event.Host
	case "template":
		subdirectory = event.TemplateID
	}
	if subdirectory != "" {
		// Sanitize the subdirectory name to remove any characters that are not allowed in a directory name
		subdirectory = sanitizeFilename(subdirectory)

		// Prepend the subdirectory name to the filename for the fileUrl
		fileUrl = filepath.Join(subdirectory, filename)

		// Create the subdirectory if it does not exist
		if err = fileutil.CreateFolders(filepath.Join(exporter.directory, subdirectory)); err != nil {
			gologger.Warning().Msgf("Could not create subdirectory for markdown report: %s", err)
		}
	}

	host := util.CreateLink(event.Host, fileUrl)
	finding := event.TemplateID + " " + event.MatcherName
	severity := event.Info.SeverityHolder.Severity.String()

	_, err = file.WriteString(util.CreateTableRow(host, finding, severity))
	if err != nil {
		return err
	}

	dataBuilder := &bytes.Buffer{}
	dataBuilder.WriteString(util.CreateHeading3(format.Summary(event)))
	dataBuilder.WriteString("\n")
	dataBuilder.WriteString(util.CreateHorizontalLine())
	dataBuilder.WriteString(format.CreateReportDescription(event, util.MarkdownFormatter{}))
	data := dataBuilder.Bytes()

	return os.WriteFile(filepath.Join(exporter.directory, subdirectory, filename), data, 0644)
}

func createFileName(event *output.ResultEvent) string {
	filenameBuilder := &strings.Builder{}
	filenameBuilder.WriteString(event.TemplateID)
	filenameBuilder.WriteString("-")
	filenameBuilder.WriteString(stringsutil.ReplaceAll(event.Matched, "_", "/", ":"))

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
	filenameBuilder.WriteString(extension)
	return sanitizeFilename(filenameBuilder.String())
}

// Close closes the exporter after operation
func (exporter *Exporter) Close() error {
	return nil
}

func sanitizeFilename(filename string) string {
	if len(filename) > 256 {
		filename = filename[0:255]
	}
	return stringsutil.ReplaceAll(filename, "_", "?", "/", ">", "|", ":", ";", "*", "<", "\"", "'", " ")
}
