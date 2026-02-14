package output

import (
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
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

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/internal/colorizer"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	protocolUtils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	Close()
	Colorizer() aurora.Aurora
	Write(*ResultEvent) error
	WriteFailure(*InternalWrappedEvent) error
	Request(templateID, url, requestType string, err error)
	RequestStatsLog(statusCode, response string)
	WriteStoreDebugData(host, templateID, eventType string, data string)
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
	AddNewLinesOutputFile bool
	KeysToRedact          []string

	// IgnoreHoneypots determines if we should skip printing honeypot results
	IgnoreHoneypots bool

	JSONLogRequestHook func(*JSONLogRequest)
	resultCount        atomic.Int32
}

var _ Writer = &StandardWriter{}
var decolorizerRegex = regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)

type JSONLogRequest struct {
	Template string `json:"template"`
	Type     string `json:"type"`
	Input    string `json:"input"`
	Address  string `json:"address"`
	Error    string `json:"error"`
	Kind     string `json:"kind,omitempty"`
}

type InternalEvent map[string]interface{}

func (ie InternalEvent) Set(k string, v interface{}) {
	ie[k] = v
}

// InternalWrappedEvent is a wrapped event with operators result added to it.
type InternalWrappedEvent struct {
	sync.RWMutex
	InternalEvent     InternalEvent
	Results           []*ResultEvent
	OperatorsResult   *operators.Result
	UsesInteractsh    bool
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
	Template         string                          `json:"template,omitempty"`
	TemplateURL      string                          `json:"template-url,omitempty"`
	TemplateID       string                          `json:"template-id"`
	TemplatePath     string                          `json:"template-path,omitempty"`
	TemplateEncoded  string                          `json:"template-encoded,omitempty"`
	Info             model.Info                      `json:"info,inline"`
	MatcherName      string                          `json:"matcher-name,omitempty"`
	ExtractorName    string                          `json:"extractor-name,omitempty"`
	Type             string                          `json:"type"`
	Host             string                          `json:"host,omitempty"`
	Port             string                          `json:"port,omitempty"`
	Scheme           string                          `json:"scheme,omitempty"`
	URL              string                          `json:"url,omitempty"`
	Path             string                          `json:"path,omitempty"`
	Matched          string                          `json:"matched-at,omitempty"`
	ExtractedResults []string                        `json:"extracted-results,omitempty"`
	Request          string                          `json:"request,omitempty"`
	Response         string                          `json:"response,omitempty"`
	Metadata         map[string]interface{}          `json:"meta,omitempty"`
	IP               string                          `json:"ip,omitempty"`
	Timestamp        time.Time                       `json:"timestamp"`
	Interaction      *server.Interaction             `json:"interaction,omitempty"`
	CURLCommand      string                          `json:"curl-command,omitempty"`
	MatcherStatus    bool                            `json:"matcher-status"`
	Lines            []int                           `json:"matched-line,omitempty"`
	GlobalMatchers   bool                            `json:"global-matchers,omitempty"`
	IssueTrackers    map[string]IssueTrackerMetadata `json:"issue_trackers,omitempty"`
	ReqURLPattern    string                          `json:"req_url_pattern,omitempty"`

	// Security Flags
	HoneypotDetected bool `json:"honeypot_detected,omitempty"`

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
	IssueID  string `json:"id,omitempty"`
	IssueURL string `json:"url,omitempty"`
}

// NewStandardWriter initializes the output writer with honeypot detection options.
func NewStandardWriter(options *types.Options) (*StandardWriter, error) {
	resumeBool := options.Resume != ""
	auroraColorizer := aurora.NewAurora(!options.NoColor)

	var outputFile, traceOutput, errorOutput io.WriteCloser
	var err error

	if options.Output != "" {
		outputFile, err = newFileOutputWriter(options.Output, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
	}
	if options.TraceLogFile != "" {
		traceOutput, err = newFileOutputWriter(options.TraceLogFile, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create trace file")
		}
	}
	if options.ErrorLogFile != "" {
		errorOutput, err = newFileOutputWriter(options.ErrorLogFile, resumeBool)
		if err != nil {
			return nil, errors.Wrap(err, "could not create error file")
		}
	}

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
		IgnoreHoneypots:  options.IgnoreHoneypots,
	}

	if v := os.Getenv("DISABLE_STDOUT"); v == "true" || v == "1" {
		writer.DisableStdout = true
	}

	return writer, nil
}

func (w *StandardWriter) ResultCount() int {
	return int(w.resultCount.Load())
}

// Write handles the final delivery of the result to terminal or file,
// including honeypot warning logic.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Must run first so honeypot warnings are visible even for filtered events.
	if event.HoneypotDetected {
		gologger.Warning().Msgf("Honeypot behavior detected for %s! Triggered %d matchers.", event.Host, len(event.ExtractedResults))
		if w.IgnoreHoneypots {
			return nil
		}
	}

	if event.Error != "" && !w.matcherStatus {
		return nil
	}

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
		return errors.Wrap(err, "failed to format output event")
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
			return errors.Wrap(writeErr, "failed to write results to output file")
		}
		if w.AddNewLinesOutputFile && w.json {
			_, _ = w.outputFile.Write([]byte("\n"))
		}
	}
	w.resultCount.Add(1)
	return nil
}

func (w *StandardWriter) Request(templateID, reqURL, requestType string, err error) {
	jsonReq := getJSONLogRequestFromError(templateID, reqURL, requestType, err)
	if w.JSONLogRequestHook != nil {
		w.JSONLogRequestHook(jsonReq)
	}

	if w.traceFile != nil {
		if data, marshalErr := json.Marshal(jsonReq); marshalErr == nil {
			_, _ = w.traceFile.Write(data)
		}
	}
	if err != nil && w.errorFile != nil {
		if data, marshalErr := json.Marshal(jsonReq); marshalErr == nil {
			_, _ = w.errorFile.Write(data)
		}
	}
}

func (w *StandardWriter) RequestStatsLog(statusCode, response string) {}

func (w *StandardWriter) WriteStoreDebugData(host, templateID, eventType, data string) {
	if !w.storeResponse {
		return
	}

	fileName := fmt.Sprintf("%s-%s-%d.txt", strings.ReplaceAll(host, string(os.PathSeparator), "_"), eventType, time.Now().UnixNano())
	if templateID != "" {
		fileName = fmt.Sprintf("%s-%s", strings.ReplaceAll(templateID, string(os.PathSeparator), "_"), fileName)
	}
	filePath := filepath.Join(w.storeResponseDir, fileName)
	_ = os.WriteFile(filePath, []byte(data), 0o600)
}

func (w *StandardWriter) encodeTemplate(templatePath string) string {
	if w.omitTemplate || templatePath == "" {
		return ""
	}
	buff, err := os.ReadFile(templatePath)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buff)
}

func redactKeys(input string, keys []string) string {
	if input == "" || len(keys) == 0 {
		return input
	}
	redacted := input
	for _, key := range keys {
		if key == "" {
			continue
		}
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)(%s\s*[:=]\s*)([^,\s&"']+)`, regexp.QuoteMeta(key)))
		redacted = pattern.ReplaceAllString(redacted, "${1}[REDACTED]")
	}
	return redacted
}

func getJSONLogRequestFromError(templateID, reqURL, requestType string, err error) *JSONLogRequest {
	jsonReq := &JSONLogRequest{
		Template: templateID,
		Type:     requestType,
		Input:    reqURL,
		Address:  getAddress(reqURL),
		Error:    "none",
	}
	if err == nil {
		return jsonReq
	}

	root := errors.Cause(err)
	if root == nil {
		root = err
	}
	for {
		unwrapped := stderrors.Unwrap(root)
		if unwrapped == nil {
			break
		}
		root = unwrapped
	}
	jsonReq.Error = fmt.Sprintf("cause=%q", root.Error())
	jsonReq.Kind = "unknown-error"
	return jsonReq
}

func getAddress(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw + ":"
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		if strings.Contains(raw, "://") {
			return raw + ":"
		}
		return raw + ":"
	}
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

func (w *StandardWriter) Colorizer() aurora.Aurora {
	return w.aurora
}

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

// WriteFailure handles failed template matches for diagnostic purposes.
func (w *StandardWriter) WriteFailure(wrappedEvent *InternalWrappedEvent) error {
	if !w.matcherStatus {
		return nil
	}

	// Pass the HoneypotDetected flag if present in OperatorsResult
	honeypot := false
	if wrappedEvent.OperatorsResult != nil {
		honeypot = wrappedEvent.OperatorsResult.HoneypotDetected
	}

	if len(wrappedEvent.Results) > 0 {
		errs := []error{}
		for _, result := range wrappedEvent.Results {
			result.MatcherStatus = false
			result.HoneypotDetected = honeypot
			if err := w.Write(result); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return multierr.Combine(errs...)
		}
		return nil
	}

	event := wrappedEvent.InternalEvent
	templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]), types.ToString(event["template-id"]), types.ToString(event["template-verifier"]))

	var templateInfo model.Info
	if event["template-info"] != nil {
		templateInfo = event["template-info"].(model.Info)
	}

	fields := protocolUtils.GetJsonFieldsFromURL(types.ToString(event["host"]))

	data := &ResultEvent{
		Template:         templatePath,
		TemplateURL:      templateURL,
		TemplateID:       types.ToString(event["template-id"]),
		TemplatePath:     types.ToString(event["template-path"]),
		Info:             templateInfo,
		Type:             types.ToString(event["type"]),
		Host:             fields.Host,
		Path:             fields.Path,
		Port:             fields.Port,
		Scheme:           fields.Scheme,
		URL:              fields.URL,
		IP:               types.ToString(event["ip"]),
		Request:          types.ToString(event["request"]),
		Response:         types.ToString(event["response"]),
		MatcherStatus:    false,
		HoneypotDetected: honeypot,
		Timestamp:        time.Now(),
		TemplateEncoded:  w.encodeTemplate(types.ToString(event["template-path"])),
		Error:            types.ToString(event["error"]),
	}
	return w.Write(data)
}
