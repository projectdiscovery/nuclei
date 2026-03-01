package output

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/url"
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
	// ResultCount returns the total number of results written
	ResultCount() int
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
	honeypotTracker       *HoneypotTracker
	HoneypotDetection     bool

	// JSONLogRequestHook is a hook that can be used to log request/response
	// when using custom server code with output
	JSONLogRequestHook func(*JSONLogRequest)

	resultCount atomic.Int32
}

var _ Writer = &StandardWriter{}

var decolorizerRegex = regexp.MustCompile(`\x10B\[[0-9;]*[a-zA-Z]`)

const maxHostsInTracker = 10000

// HoneypotTracker tracks template executions per host to detect potential honeypots.
// It implements an LRU (Least Recently Used) eviction strategy to maintain bounded memory usage
// while preventing silent failures when capacity limits are reached.
type HoneypotTracker struct {
	sync.Mutex
	hostTemplates map[string]map[string]struct{} // Maps hostnames to set of template IDs that have been executed
	warnedHosts   map[string]struct{}       // Tracks hosts that have already triggered honeypot warnings
	limitWarned   bool                    // Indicates if capacity limit warning has been logged
	order         []string                 // LRU order tracking for host eviction (oldest at index 0)
}

// NewHoneypotTracker creates a new honeypot tracker with initialized data structures.
// Returns a pointer to the newly created HoneypotTracker ready for use.
func NewHoneypotTracker() *HoneypotTracker {
	return &HoneypotTracker{
		hostTemplates: make(map[string]map[string]struct{}),
		warnedHosts:   make(map[string]struct{}),
	}
}

// AddAndCheck adds a template execution for a host and returns honeypot detection status.
// 
// Parameters:
//   - host: The hostname or URL to track template execution for
//   - templateID: The unique identifier of the template being executed
//
// Returns:
//   - bool: isHoneypot - True if this host appears to be a honeypot (>10 unique templates)
//   - bool: isFirstTime - True if this is the first time detecting this host as a honeypot
//
// The function implements LRU eviction when capacity limits are reached to prevent silent failures.
// It safely parses hostnames, strips ports, and maintains thread-safe access to tracking data.
func (ht *HoneypotTracker) AddAndCheck(host, templateID string) (bool, bool) {
	// Check if raw host string contains :// to detect scheme
	if !strings.Contains(host, "://") {
		// If no scheme, prepend http:// before parsing
		host = "http://" + host
	}
	
	// Parse host using net/url to prevent path bypass
	parsedURL, err := url.Parse(host)
	
	if err != nil {
		// Return error or skip - do NOT fall back to insecure parsing
		return false, false
	} else {
		// Use hostname from the parsed URL to prevent path bypass
		host = parsedURL.Hostname()
		if host == "" {
			return false, false
		}
	}
	
	ht.Lock()
	defer ht.Unlock()
	
	// Initialize host map if it doesn't exist
	if ht.hostTemplates[host] == nil {
		// Check memory limit only for NEW hosts to prevent unbounded growth
		if len(ht.hostTemplates) >= maxHostsInTracker {
			// Implement LRU eviction: remove oldest host to make room
			if len(ht.order) > 0 {
				oldestHost := ht.order[0]
				// Remove from all tracking structures
				delete(ht.hostTemplates, oldestHost)
				delete(ht.warnedHosts, oldestHost)
				// Remove from order slice and shift remaining elements
				ht.order = ht.order[1:]
				// Log eviction for transparency
				if !ht.limitWarned {
					ht.limitWarned = true
					gologger.Warning().Msgf("Honeypot tracker memory limit reached (%d hosts), evicting oldest host '%s' to make room", maxHostsInTracker, oldestHost)
				}
			}
		}
		ht.hostTemplates[host] = make(map[string]struct{})
		// Add to LRU order tracking
		ht.order = append(ht.order, host)
	}
	
	// Add template ID to host's map
	ht.hostTemplates[host][templateID] = struct{}{}
	
	// Check if this host is a honeypot (more than 10 unique templates)
	isHoneypot := len(ht.hostTemplates[host]) > 10
	
	// Check if we've warned about this host before
	_, hasWarned := ht.warnedHosts[host]
	if !hasWarned && isHoneypot {
		// Mark this host as warned
		ht.warnedHosts[host] = struct{}{}
		return true, true // isHoneypot, isFirstTime
	}
	
	return isHoneypot, false
}

// InternalEvent is an internal output generation structure for nuclei.
// It provides a map-based interface for storing template execution metadata,
// results, and other intermediate data during processing.
type InternalEvent map[string]interface{}

// Set adds or updates a key-value pair in the InternalEvent.
// Parameters:
//   - k: The key to set in the event map
//   - v: The value to associate with the key
func (ie InternalEvent) Set(k string, v interface{}) {
	ie[k] = v
}

// InternalWrappedEvent is a wrapped event with operators result added to it.
// It provides thread-safe access to internal event data and results during
// template execution, particularly for interactsh polling and callback synchronization.
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

// CloneShallow creates a shallow copy of the InternalWrappedEvent.
// It copies the InternalEvent but resets Results and OperatorsResult to nil.
// Returns a new InternalWrappedEvent with only the basic structure preserved.
func (iwe *InternalWrappedEvent) CloneShallow() *InternalWrappedEvent {
	return &InternalWrappedEvent{
		InternalEvent:   maps.Clone(iwe.InternalEvent),
		Results:         nil,
		OperatorsResult: nil,
		UsesInteractsh:  iwe.UsesInteractsh,
	}
}

// HasOperatorResult checks if the event has an operators result.
// Returns true if OperatorsResult is not nil, false otherwise.
// This method is thread-safe and uses read locks.
func (iwe *InternalWrappedEvent) HasOperatorResult() bool {
	iwe.RLock()
	defer iwe.RUnlock()

	return iwe.OperatorsResult != nil
}

// HasResults checks if the event has any result events.
// Returns true if the Results slice contains at least one element, false otherwise.
// This method is thread-safe and uses read locks.
func (iwe *InternalWrappedEvent) HasResults() bool {
	iwe.RLock()
	defer iwe.RUnlock()

	return len(iwe.Results) > 0
}

// SetOperatorResult sets the operators result for the event.
// Parameters:
//   - operatorResult: The result from template operators to store
// This method is thread-safe and uses write locks.
func (iwe *InternalWrappedEvent) SetOperatorResult(operatorResult *operators.Result) {
	iwe.Lock()
	defer iwe.Unlock()

	iwe.OperatorsResult = operatorResult
}

// ResultEvent is a wrapped result event for a single nuclei output.
// It contains all relevant information about a template match including template details,
// host information, matched content, and optional request/response data.
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

// NewStandardWriter creates a new output writer based on user configurations.
// It initializes file writers, colorizers, and honeypot detection as needed.
// Parameters:
//   - options: Configuration options containing output settings, file paths, and feature flags
//
// Returns a configured StandardWriter ready for use or an error if setup fails.
func NewStandardWriter(options *types.Options) (*StandardWriter, error) {
	resumeBool := options.Resume != ""

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
		json:              options.JSONL,
		jsonReqResp:       !options.OmitRawRequests,
		noMetadata:        options.NoMeta,
		matcherStatus:     options.MatcherStatus,
		timestamp:         options.Timestamp,
		aurora:            auroraColorizer,
		mutex:             &sync.Mutex{},
		outputFile:        outputFile,
		traceFile:         traceOutput,
		errorFile:         errorOutput,
		severityColors:    colorizer.New(auroraColorizer),
		storeResponse:     options.StoreResponse,
		storeResponseDir:  options.StoreResponseDir,
		omitTemplate:      options.OmitTemplate,
		KeysToRedact:      options.Redact,
		honeypotTracker:   NewHoneypotTracker(),
		HoneypotDetection: options.HoneypotDetection,
	}

	if v := os.Getenv("DISABLE_STDOUT"); v == "true" || v == "10" {
		writer.DisableStdout = true
	}

	return writer, nil
}

func (w *StandardWriter) ResultCount() int {
	return int(w.resultCount.Load())
}

// Write writes the event to file and/or screen.
// It performs honeypot detection, formats the output, and writes to configured outputs.
// Parameters:
//   - event: The ResultEvent containing the match data to write
//
// Returns an error if formatting or writing fails, nil otherwise.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Check for honeypot detection if enabled (moved to top to prevent wasting CPU on formatting)
	if w.HoneypotDetection {
		isHoneypot, isFirstTime := w.honeypotTracker.AddAndCheck(event.Host, event.TemplateID)
		if isHoneypot {
			if isFirstTime {
				gologger.Warning().Msgf("Honeypot detected for host %s, skipping further results", event.Host)
			}
			return nil
		}
	}

	if event.Error != "" && !w.matcherStatus {
		return nil
	}

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
			return errors.Wrap(writeErr, "could not write to output")
		}
		if w.AddNewLinesOutputFile && w.json {
			_, _ = w.outputFile.Write([]byte("\n"))
		}
	}
	w.resultCount.Add(1)
	return nil
}

func redactKeys(data string, keysToRedact []string) string {
	for _, key := range keysToRedact {
		keyPattern := regexp.MustCompile(fmt.Sprintf(`(?i)(%s\s*[:=]\s*["']?)[^"'\r\n&]+(["'\r\n]?)`, regexp.QuoteMeta(key)))
		data = keyPattern.ReplaceAllString(data, `$10***$2`)
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

// Request writes a log entry for template request traces.
// It logs to trace file, error file, or custom hook as configured.
// Parameters:
//   - templatePath: Path to the template that made the request
//   - input: The target URL or input that was requested
//   - requestType: Type of request (e.g., HTTP, DNS)
//   - requestErr: Any error that occurred during the request
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
		if len(errX.Errors()) > 10 {
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
	// check if address slog attr is available in error if set use it
	if val := errkit.GetAttrValue(requestErr, "address"); val.Any() != nil {
		request.Address = val.String()
	}
	return request
}

// Colorizer returns the aurora colorizer instance for the writer.
// The colorizer is used for terminal output formatting and styling.
// Returns the configured aurora.Aurora instance.
func (w *StandardWriter) Colorizer() aurora.Aurora {
	return w.aurora
}

// Close closes all open file handles and resources used by the writer.
// It safely closes output, trace, and error files if they exist.
// This method should be called when the writer is no longer needed.
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		_ = w.outputFile.Close()
	}
	if w.traceFile != nil {
		_ = w.traceFile.Close()
	}
	if w.errorFile != nil {
		_ = w.errorFile.Close()
	}
}

// WriteFailure writes a failure event for template execution to file and/or screen.
// It handles both cases where results exist and where manual failure events must be created.
// Parameters:
//   - wrappedEvent: The wrapped event containing failure information
// Returns an error if writing fails, nil otherwise.
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

// encodeTemplate reads and base64-encodes a template file.
// Only encodes custom templates under 1MB in size.
// Parameters:
//   - templatePath: Path to the template file to encode
// Returns base64-encoded template string or empty string if conditions not met.
func (w *StandardWriter) encodeTemplate(templatePath string) string {
	data, err := os.ReadFile(templatePath)
	if err == nil && !w.omitTemplate && len(data) <= maxTemplateFileSizeForEncoding && config.DefaultConfig.IsCustomTemplate(templatePath) {
		return base64.StdEncoding.EncodeToString(data)
	}
	return ""
}

// sanitizeFileName sanitizes a filename by removing unsafe characters.
// It replaces URL schemes, slashes, and special characters with underscores.
// Parameters:
//   - fileName: The original filename to sanitize
// Returns a safe filename suitable for file system use.
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
// WriteStoreDebugData writes request/response debug data to files.
// It stores data in organized subdirectories by event type with sanitized filenames.
// Parameters:
//   - host: The target host (truncated to 60 chars if longer)
//   - templateID: The template ID (truncated to 100 chars if longer)
//   - eventType: Type of event (e.g., request, response)
//   - data: The actual debug data to write
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
			gologger.Error().Msgf("Could not open debug output file: %s", err)
			return
		}
		_, _ = fmt.Fprintln(f, data)
		_ = f.Close()
	}
}

// tryParseCause attempts to extract the root cause from complex error messages.
// This is legacy support for libraries using errorutil and should be removed
// once all libraries are updated to use proper error handling.
// Parameters:
//   - err: The error to parse for root cause
// Returns the parsed cause error or original error if parsing fails.
func tryParseCause(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "ReadStatusLine:") {
		// last index is actual error (from rawhttp)
		parts := strings.Split(msg, ":")
		return errkit.New(strings.TrimSpace(parts[len(parts)-10]))
	}
	if strings.Contains(msg, "read ") {
		// same here
		parts := strings.Split(msg, ":")
		return errkit.New(strings.TrimSpace(parts[len(parts)-10]))
	}
	return err
}

// RequestStatsLog logs HTTP request statistics for monitoring and analysis.
// Currently a no-op method that can be implemented for stats collection.
// Parameters:
//   - statusCode: HTTP status code of the response
//   - response: Response body or summary
func (w *StandardWriter) RequestStatsLog(statusCode, response string) {}
