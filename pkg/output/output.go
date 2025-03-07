package output

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	protocolUtils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/nucleierr"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
	unitutils "github.com/projectdiscovery/utils/unit"
	urlutil "github.com/projectdiscovery/utils/url"
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
	WriteFailure(*InternalWrappedEvent) error
	// Request logs a request in the trace log
	Request(templateID, url, requestType string, err error)
	// RequestStatsLog logs a request stats log
	RequestStatsLog(statusCode, response string)
	//  WriteStoreDebugData writes the request/response debug data to file
	WriteStoreDebugData(host, templateID, eventType string, data string)
}

// StandardWriter is a writer writing output to file and screen for results.
type StandardWriter struct {
	json                  bool
	jsonReqResp           bool
	timestamp             bool
	noMetadata            bool
	matcherStatus         bool
	mutex                 *sync.Mutex
	aurora                aurora.Aurora
	outputFile            io.WriteCloser
	traceFile             io.WriteCloser
	errorFile             io.WriteCloser
	severityColors        func(severity.Severity) string
	storeResponse         bool
	storeResponseDir      string
	omitTemplate          bool
	DisableStdout         bool
	AddNewLinesOutputFile bool // by default this is only done for stdout
	KeysToRedact          []string

	// JSONLogRequestHook is a hook that can be used to log request/response
	// when using custom server code with output
	JSONLogRequestHook func(*JSONLogRequest)
}

var _ Writer = &StandardWriter{}

var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

// InternalEvent is an internal output generation structure for nuclei.
type InternalEvent map[string]interface{}

func (ie InternalEvent) Set(k string, v interface{}) {
	ie[k] = v
}

// InternalWrappedEvent is a wrapped event with operators result added to it.
type InternalWrappedEvent struct {
	// Mutex is internal field which is implicitly used
	// to synchronize callback(event) and interactsh polling updates
	// Refer protocols/http.Request.ExecuteWithResults for more details
	sync.RWMutex

	InternalEvent   InternalEvent
	Results         []*ResultEvent
	OperatorsResult *operators.Result
	UsesInteractsh  bool
	// Only applicable if interactsh is used
	// This is used to avoid duplicate successful interactsh events
	InteractshMatched atomic.Bool
}

func (iwe *InternalWrappedEvent) CloneShallow() *InternalWrappedEvent {
	return &InternalWrappedEvent{
		InternalEvent:   maps.Clone(iwe.InternalEvent),
		Results:         nil,
		OperatorsResult: nil,
		UsesInteractsh:  iwe.UsesInteractsh,
	}
}

func (iwe *InternalWrappedEvent) HasOperatorResult() bool {
	iwe.RLock()
	defer iwe.RUnlock()

	return iwe.OperatorsResult != nil
}

func (iwe *InternalWrappedEvent) HasResults() bool {
	iwe.RLock()
	defer iwe.RUnlock()

	return len(iwe.Results) > 0
}

func (iwe *InternalWrappedEvent) SetOperatorResult(operatorResult *operators.Result) {
	iwe.Lock()
	defer iwe.Unlock()

	iwe.OperatorsResult = operatorResult
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
	TemplatePath string `json:"template-path,omitempty"`
	// TemplateEncoded is the base64 encoded template
	TemplateEncoded string `json:"template-encoded,omitempty"`
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
	// Port is port of the host input on which match was found (if applicable).
	Port string `json:"port,omitempty"`
	// Scheme is the scheme of the host input on which match was found (if applicable).
	Scheme string `json:"scheme,omitempty"`
	// URL is the Base URL of the host input on which match was found (if applicable).
	URL string `json:"url,omitempty"`
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
	MatcherStatus bool `json:"matcher-status"`
	// Lines is the line count for the specified match
	Lines []int `json:"matched-line,omitempty"`
	// GlobalMatchers identifies whether the matches was detected in the response
	// of another template's result event
	GlobalMatchers bool `json:"global-matchers,omitempty"`

	// IssueTrackers is the metadata for issue trackers
	IssueTrackers map[string]IssueTrackerMetadata `json:"issue_trackers,omitempty"`
	// ReqURLPattern when enabled contains base URL pattern that was used to generate the request
	// must be enabled by setting protocols.ExecuterOptions.ExportReqURLPattern to true
	ReqURLPattern string `json:"req_url_pattern,omitempty"`

	// Fields related to HTTP Fuzzing functionality of nuclei.
	// The output contains additional fields when the result is
	// for a fuzzing template.
	IsFuzzingResult  bool   `json:"is_fuzzing_result,omitempty"`
	FuzzingMethod    string `json:"fuzzing_method,omitempty"`
	FuzzingParameter string `json:"fuzzing_parameter,omitempty"`
	FuzzingPosition  string `json:"fuzzing_position,omitempty"`
	AnalyzerDetails  string `json:"analyzer_details,omitempty"`

	FileToIndexPosition map[string]int `json:"-"`
	TemplateVerifier    string         `json:"-"`
	Error               string         `json:"error,omitempty"`
}

type IssueTrackerMetadata struct {
	// IssueID is the ID of the issue created
	IssueID string `json:"id,omitempty"`
	// IssueURL is the URL of the issue created
	IssueURL string `json:"url,omitempty"`
}

// NewStandardWriter creates a new output writer based on user configurations
func NewStandardWriter(options *types.Options) (*StandardWriter, error) {
	resumeBool := false
	if options.Resume != "" {
		resumeBool = true
	}
	auroraColorizer := aurora.NewAurora(!options.NoColor)

	var outputFile io.WriteCloser
	if options.Output != "" {
		output, err := newFileOutputWriter(options.Output, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}
	var traceOutput io.WriteCloser
	if options.TraceLogFile != "" {
		output, err := newFileOutputWriter(options.TraceLogFile, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		traceOutput = output
	}
	var errorOutput io.WriteCloser
	if options.ErrorLogFile != "" {
		output, err := newFileOutputWriter(options.ErrorLogFile, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create error file")
		}
		errorOutput = output
	}
	// Try to create output folder if it doesn't exist
	if options.StoreResponse && !fileutil.FolderExists(options.StoreResponseDir) {
		if err := fileutil.CreateFolder(options.StoreResponseDir); err != nil {
			gologger.Fatal().Msgf("Could not create output directory '%s': %s\n", options.StoreResponseDir, err)
		}
	}

	writer := &StandardWriter{
		json:             options.JSONL,
		jsonReqResp:      !options.OmitRawRequests,
		noMetadata:       options.NoMeta,
		matcherStatus:    options.MatcherStatus,
		timestamp:        options.Timestamp,
		aurora:           auroraColorizer,
		mutex:            &sync.Mutex{},
		outputFile:       outputFile,
		traceFile:        traceOutput,
		errorFile:        errorOutput,
		severityColors:   colorizer.New(auroraColorizer),
		storeResponse:    options.StoreResponse,
		storeResponseDir: options.StoreResponseDir,
		omitTemplate:     options.OmitTemplate,
		KeysToRedact:     options.Redact,
	}

	if v := os.Getenv("DISABLE_STDOUT"); v == "true" || v == "1" {
		writer.DisableStdout = true
	}

	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Enrich the result event with extra metadata on the template-path and url.
	if event.TemplatePath != "" {
		event.Template, event.TemplateURL = utils.TemplatePathURL(types.ToString(event.TemplatePath), types.ToString(event.TemplateID), event.TemplateVerifier)
	}

	if len(w.KeysToRedact) > 0 {
		event.Request = redactKeys(event.Request, w.KeysToRedact)
		event.Response = redactKeys(event.Response, w.KeysToRedact)
		event.CURLCommand = redactKeys(event.CURLCommand, w.KeysToRedact)
		event.Matched = redactKeys(event.Matched, w.KeysToRedact)
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
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if !w.DisableStdout {
		_, _ = os.Stdout.Write(data)
		_, _ = os.Stdout.Write([]byte("\n"))
	}

	if w.outputFile != nil {
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
		if w.AddNewLinesOutputFile && w.json {
			_, _ = w.outputFile.Write([]byte("\n"))
		}
	}
	return nil
}

func redactKeys(data string, keysToRedact []string) string {
	for _, key := range keysToRedact {
		keyPattern := regexp.MustCompile(fmt.Sprintf(`(?i)(%s\s*[:=]\s*["']?)[^"'\r\n&]+(["'\r\n]?)`, regexp.QuoteMeta(key)))
		data = keyPattern.ReplaceAllString(data, `$1***$2`)
	}
	return data
}

// JSONLogRequest is a trace/error log request written to file
type JSONLogRequest struct {
	Template  string      `json:"template"`
	Type      string      `json:"type"`
	Input     string      `json:"input"`
	Timestamp *time.Time  `json:"timestamp,omitempty"`
	Address   string      `json:"address"`
	Error     string      `json:"error"`
	Kind      string      `json:"kind,omitempty"`
	Attrs     interface{} `json:"attrs,omitempty"`
}

// Request writes a log the requests trace log
func (w *StandardWriter) Request(templatePath, input, requestType string, requestErr error) {
	if w.traceFile == nil && w.errorFile == nil && w.JSONLogRequestHook == nil {
		return
	}

	request := getJSONLogRequestFromError(templatePath, input, requestType, requestErr)
	if w.timestamp {
		ts := time.Now()
		request.Timestamp = &ts
	}
	data, err := jsoniter.Marshal(request)
	if err != nil {
		return
	}

	if w.JSONLogRequestHook != nil {
		w.JSONLogRequestHook(request)
	}

	if w.traceFile != nil {
		_, _ = w.traceFile.Write(data)
	}

	if requestErr != nil && w.errorFile != nil {
		_, _ = w.errorFile.Write(data)
	}
}

func getJSONLogRequestFromError(templatePath, input, requestType string, requestErr error) *JSONLogRequest {
	request := &JSONLogRequest{
		Template: templatePath,
		Input:    input,
		Type:     requestType,
	}

	parsed, _ := urlutil.ParseAbsoluteURL(input, false)
	if parsed != nil {
		request.Address = parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			switch parsed.Scheme {
			case urlutil.HTTP:
				port = "80"
			case urlutil.HTTPS:
				port = "443"
			}
		}
		request.Address += ":" + port
	}
	errX := errkit.FromError(requestErr)
	if errX == nil {
		request.Error = "none"
	} else {
		request.Kind = errkit.ErrKindUnknown.String()
		var cause error
		if len(errX.Errors()) > 1 {
			cause = errX.Errors()[0]
		}
		if cause == nil {
			cause = errX
		}
		cause = tryParseCause(cause)
		request.Error = cause.Error()
		request.Kind = errkit.GetErrorKind(requestErr, nucleierr.ErrTemplateLogic).String()
		if len(errX.Attrs()) > 0 {
			request.Attrs = slog.GroupValue(errX.Attrs()...)
		}
	}
	// check if address slog attr is avaiable in error if set use it
	if val := errkit.GetAttrValue(requestErr, "address"); val.Any() != nil {
		request.Address = val.String()
	}
	return request
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
func (w *StandardWriter) WriteFailure(wrappedEvent *InternalWrappedEvent) error {
	if !w.matcherStatus {
		return nil
	}
	if len(wrappedEvent.Results) > 0 {
		errs := []error{}
		for _, result := range wrappedEvent.Results {
			result.MatcherStatus = false // just in case
			if err := w.Write(result); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return multierr.Combine(errs...)
		}
		return nil
	}
	// if no results were found, manually create a failure event
	event := wrappedEvent.InternalEvent

	templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]), types.ToString(event["template-id"]), types.ToString(event["template-verifier"]))
	var templateInfo model.Info
	if event["template-info"] != nil {
		templateInfo = event["template-info"].(model.Info)
	}
	fields := protocolUtils.GetJsonFieldsFromURL(types.ToString(event["host"]))
	if types.ToString(event["ip"]) != "" {
		fields.Ip = types.ToString(event["ip"])
	}
	if types.ToString(event["path"]) != "" {
		fields.Path = types.ToString(event["path"])
	}

	data := &ResultEvent{
		Template:      templatePath,
		TemplateURL:   templateURL,
		TemplateID:    types.ToString(event["template-id"]),
		TemplatePath:  types.ToString(event["template-path"]),
		Info:          templateInfo,
		Type:          types.ToString(event["type"]),
		Host:          fields.Host,
		Path:          fields.Path,
		Port:          fields.Port,
		Scheme:        fields.Scheme,
		URL:           fields.URL,
		IP:            fields.Ip,
		Request:       types.ToString(event["request"]),
		Response:      types.ToString(event["response"]),
		MatcherStatus: false,
		Timestamp:     time.Now(),
		//FIXME: this is workaround to encode the template when no results were found
		TemplateEncoded: w.encodeTemplate(types.ToString(event["template-path"])),
		Error:           types.ToString(event["error"]),
	}
	return w.Write(data)
}

var maxTemplateFileSizeForEncoding = unitutils.Mega

func (w *StandardWriter) encodeTemplate(templatePath string) string {
	data, err := os.ReadFile(templatePath)
	if err == nil && !w.omitTemplate && len(data) <= maxTemplateFileSizeForEncoding && config.DefaultConfig.IsCustomTemplate(templatePath) {
		return base64.StdEncoding.EncodeToString(data)
	}
	return ""
}

func sanitizeFileName(fileName string) string {
	fileName = strings.ReplaceAll(fileName, "http:", "")
	fileName = strings.ReplaceAll(fileName, "https:", "")
	fileName = strings.ReplaceAll(fileName, "/", "_")
	fileName = strings.ReplaceAll(fileName, "\\", "_")
	fileName = strings.ReplaceAll(fileName, "-", "_")
	fileName = strings.ReplaceAll(fileName, ".", "_")
	if osutils.IsWindows() {
		fileName = strings.ReplaceAll(fileName, ":", "_")
	}
	fileName = strings.TrimPrefix(fileName, "__")
	return fileName
}
func (w *StandardWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	if w.storeResponse {
		if len(host) > 60 {
			host = host[:57] + "..."
		}
		if len(templateID) > 100 {
			templateID = templateID[:97] + "..."
		}

		filename := sanitizeFileName(fmt.Sprintf("%s_%s", host, templateID))
		subFolder := filepath.Join(w.storeResponseDir, sanitizeFileName(eventType))
		if !fileutil.FolderExists(subFolder) {
			_ = fileutil.CreateFolder(subFolder)
		}
		filename = filepath.Join(subFolder, fmt.Sprintf("%s.txt", filename))
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Print(err)
			return
		}
		_, _ = f.WriteString(fmt.Sprintln(data))
		f.Close()
	}
}

// tryParseCause tries to parse the cause of given error
// this is legacy support due to use of errorutil in existing libraries
// but this should not be required once all libraries are updated
func tryParseCause(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "ReadStatusLine:") {
		// last index is actual error (from rawhttp)
		parts := strings.Split(msg, ":")
		return errkit.New(strings.TrimSpace(parts[len(parts)-1]))
	}
	if strings.Contains(msg, "read ") {
		// same here
		parts := strings.Split(msg, ":")
		return errkit.New(strings.TrimSpace(parts[len(parts)-1]))
	}
	return err
}

func (w *StandardWriter) RequestStatsLog(statusCode, response string) {}
