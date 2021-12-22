package output

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"regexp"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v2/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	// Close closes the output writer interface
	Close()
	// Colorizer returns the colorizer instance for writer
	Colorizer() aurora.Aurora
	// Write writes the event to file and/or screen.
	Write(*ResultEvent) error
	// WriteFailure writes the optional failure event for template to file and/or screen.
	WriteFailure(event InternalEvent) error
	// Request logs a request in the trace log
	Request(templateID, url, requestType string, err error)
}

// StandardWriter is a writer writing output to file and screen for results.
type StandardWriter struct {
	json           bool
	jsonReqResp    bool
	noTimestamp    bool
	noMetadata     bool
	matcherStatus  bool
	aurora         aurora.Aurora
	outputFile     io.WriteCloser
	traceFile      io.WriteCloser
	errorFile      io.WriteCloser
	severityColors func(severity.Severity) string
}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

// InternalEvent is an internal output generation structure for nuclei.
type InternalEvent map[string]interface{}

// DebugEvent is an event containing debug info for request execution
type DebugEvent struct {
	Request  string
	Response string
}

// InternalWrappedEvent is a wrapped event with operators result added to it.
type InternalWrappedEvent struct {
	InternalEvent   InternalEvent
	Results         []*ResultEvent
	OperatorsResult *operators.Result
	Debug           *DebugEvent
	UsesInteractsh  bool
}

// ResultEvent is a wrapped result event for a single nuclei output.
type ResultEvent struct {
	// Template is the relative filename for the template
	Template string `json:"template,omitempty"`
	// TemplateURL is the URL of the template for the result inside the nuclei
	// templates repository if it belongs to the repository.
	TemplateURL string `json:"template-url,omitempty"`
	// TemplateID is the ID of the template for the result.
	TemplateID string `json:"template-id"`
	// TemplatePath is the path of template
	TemplatePath string `json:"-"`
	// Info contains information block of the template for the result.
	Info model.Info `json:"info,inline"`
	// MatcherName is the name of the matcher matched if any.
	MatcherName string `json:"matcher-name,omitempty"`
	// ExtractorName is the name of the extractor matched if any.
	ExtractorName string `json:"extractor-name,omitempty"`
	// Type is the type of the result event.
	Type string `json:"type"`
	// Host is the host input on which match was found.
	Host string `json:"host,omitempty"`
	// Path is the path input on which match was found.
	Path string `json:"path,omitempty"`
	// Matched contains the matched input in its transformed form.
	Matched string `json:"matched-at,omitempty"`
	// ExtractedResults contains the extraction result from the inputs.
	ExtractedResults []string `json:"extracted-results,omitempty"`
	// Request is the optional, dumped request for the match.
	Request string `json:"request,omitempty"`
	// Response is the optional, dumped response for the match.
	Response string `json:"response,omitempty"`
	// Metadata contains any optional metadata for the event
	Metadata map[string]interface{} `json:"meta,omitempty"`
	// IP is the IP address for the found result event.
	IP string `json:"ip,omitempty"`
	// Timestamp is the time the result was found at.
	Timestamp time.Time `json:"timestamp"`
	// Interaction is the full details of interactsh interaction.
	Interaction *server.Interaction `json:"interaction,omitempty"`
	// CURLCommand is an optional curl command to reproduce the request
	// Only applicable if the report is for HTTP.
	CURLCommand string `json:"curl-command,omitempty"`
	// MatcherStatus is the status of the match
	MatcherStatus       bool           `json:"matcher-status"`
	FileToIndexPosition map[string]int `json:"-"`
}

func (result *ResultEvent) Hash() string {
	hasher := sha1.New()
	if result.TemplateID != "" {
		_, _ = hasher.Write(unsafeToBytes(result.TemplateID))
	}
	if result.MatcherName != "" {
		_, _ = hasher.Write(unsafeToBytes(result.MatcherName))
	}
	if result.ExtractorName != "" {
		_, _ = hasher.Write(unsafeToBytes(result.ExtractorName))
	}
	if result.Type != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Type))
	}
	if result.Host != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Host))
	}
	if result.Matched != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Matched))
	}
	for _, v := range result.ExtractedResults {
		_, _ = hasher.Write(unsafeToBytes(v))
	}
	for k, v := range result.Metadata {
		_, _ = hasher.Write(unsafeToBytes(k))
		_, _ = hasher.Write(unsafeToBytes(types.ToString(v)))
	}
	hash := hasher.Sum(nil)

	return hex.EncodeToString(hash)
}

// unsafeToBytes converts a string to byte slice and does it with
// zero allocations.
//
// Reference - https://stackoverflow.com/questions/59209493/how-to-use-unsafe-get-a-byte-slice-from-a-string-without-memory-copy
func unsafeToBytes(data string) []byte {
	var buf = *(*[]byte)(unsafe.Pointer(&data))
	(*reflect.SliceHeader)(unsafe.Pointer(&buf)).Cap = len(data)
	return buf
}

// NewStandardWriter creates a new output writer based on user configurations
func NewStandardWriter(colors, noMetadata, noTimestamp, json, jsonReqResp, MatcherStatus bool, file, traceFile string, errorFile string) (*StandardWriter, error) {
	auroraColorizer := aurora.NewAurora(colors)

	var outputFile io.WriteCloser
	if file != "" {
		output, err := newFileOutputWriter(file)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}
	var traceOutput io.WriteCloser
	if traceFile != "" {
		output, err := newFileOutputWriter(traceFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		traceOutput = output
	}
	var errorOutput io.WriteCloser
	if errorFile != "" {
		output, err := newFileOutputWriter(errorFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create error file")
		}
		errorOutput = output
	}
	writer := &StandardWriter{
		json:           json,
		jsonReqResp:    jsonReqResp,
		noMetadata:     noMetadata,
		matcherStatus:  MatcherStatus,
		noTimestamp:    noTimestamp,
		aurora:         auroraColorizer,
		outputFile:     outputFile,
		traceFile:      traceOutput,
		errorFile:      errorOutput,
		severityColors: colorizer.New(auroraColorizer),
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Enrich the result event with extra metadata on the template-path and url.
	if event.TemplatePath != "" {
		event.Template, event.TemplateURL = utils.TemplatePathURL(types.ToString(event.TemplatePath))
	}
	event.Timestamp = time.Now()

	var data []byte
	var err error

	if w.json {
		data, err = w.formatJSON(event)
	} else {
		data = w.formatScreen(event)
	}
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	_, _ = os.Stdout.Write(data)
	_, _ = os.Stdout.Write([]byte("\n"))
	if w.outputFile != nil {
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}

// JSONLogRequest is a trace/error log request written to file
type JSONLogRequest struct {
	Template string `json:"template"`
	Input    string `json:"input"`
	Error    string `json:"error"`
	Type     string `json:"type"`
}

// Request writes a log the requests trace log
func (w *StandardWriter) Request(templatePath, input, requestType string, requestErr error) {
	if w.traceFile == nil && w.errorFile == nil {
		return
	}
	request := &JSONLogRequest{
		Template: templatePath,
		Input:    input,
		Type:     requestType,
	}
	if unwrappedErr := utils.UnwrapError(requestErr); unwrappedErr != nil {
		request.Error = unwrappedErr.Error()
	} else {
		request.Error = "none"
	}

	data, err := jsoniter.Marshal(request)
	if err != nil {
		return
	}

	if w.traceFile != nil {
		_, _ = w.traceFile.Write(data)
	}

	if requestErr != nil && w.errorFile != nil {
		_, _ = w.errorFile.Write(data)
	}
}

// Colorizer returns the colorizer instance for writer
func (w *StandardWriter) Colorizer() aurora.Aurora {
	return w.aurora
}

// Close closes the output writing interface
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		w.outputFile.Close()
	}
	if w.traceFile != nil {
		w.traceFile.Close()
	}
	if w.errorFile != nil {
		w.errorFile.Close()
	}
}

// WriteFailure writes the failure event for template to file and/or screen.
func (w *StandardWriter) WriteFailure(event InternalEvent) error {
	if !w.matcherStatus {
		return nil
	}
	templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]))
	data := &ResultEvent{
		Template:      templatePath,
		TemplateURL:   templateURL,
		TemplateID:    types.ToString(event["template-id"]),
		TemplatePath:  types.ToString(event["template-path"]),
		Info:          event["template-info"].(model.Info),
		Type:          types.ToString(event["type"]),
		Host:          types.ToString(event["host"]),
		MatcherStatus: false,
		Timestamp:     time.Now(),
	}
	return w.Write(data)
}
