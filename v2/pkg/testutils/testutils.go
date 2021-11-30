package testutils

import (
	"go.uber.org/ratelimit"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Init initializes the protocols and their configurations
func Init(options *types.Options) {
	_ = protocolinit.Init(options)
}

// DefaultOptions is the default options structure for nuclei during mocking.
var DefaultOptions = &types.Options{
	Metrics:                    false,
	Debug:                      false,
	DebugRequests:              false,
	DebugResponse:              false,
	Silent:                     false,
	Version:                    false,
	Verbose:                    false,
	NoColor:                    true,
	UpdateTemplates:            false,
	JSON:                       false,
	JSONRequests:               false,
	EnableProgressBar:          false,
	TemplatesVersion:           false,
	TemplateList:               false,
	Stdin:                      false,
	StopAtFirstMatch:           false,
	NoMeta:                     false,
	Project:                    false,
	MetricsPort:                0,
	BulkSize:                   25,
	TemplateThreads:            10,
	Timeout:                    5,
	Retries:                    1,
	RateLimit:                  150,
	ProjectPath:                "",
	Severities:                 severity.Severities{},
	Targets:                    []string{},
	TargetsFilePath:            "",
	Output:                     "",
	Proxy:                      []string{},
	TemplatesDirectory:         "",
	TraceLogFile:               "",
	Templates:                  []string{},
	ExcludedTemplates:          []string{},
	CustomHeaders:              []string{},
	InteractshURL:              "https://interactsh.com",
	InteractionsCacheSize:      5000,
	InteractionsEviction:       60,
	InteractionsCoolDownPeriod: 5,
	InteractionsPollDuration:   5,
}

// TemplateInfo contains info for a mock executed template.
type TemplateInfo struct {
	ID   string
	Info model.Info
	Path string
}

// NewMockExecuterOptions creates a new mock executeroptions struct
func NewMockExecuterOptions(options *types.Options, info *TemplateInfo) *protocols.ExecuterOptions {
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	executerOpts := &protocols.ExecuterOptions{
		TemplateID:   info.ID,
		TemplateInfo: info.Info,
		TemplatePath: info.Path,
		Output:       NewMockOutputWriter(),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      catalog.New(options.TemplatesDirectory),
		RateLimiter:  ratelimit.New(options.RateLimit),
	}
	return executerOpts
}

// NoopWriter is a NooP gologger writer.
type NoopWriter struct{}

// Write writes the data to an output writer.
func (n *NoopWriter) Write(data []byte, level levels.Level) {}

// MockOutputWriter is a mocked output writer.
type MockOutputWriter struct {
	aurora          aurora.Aurora
	RequestCallback func(templateID, url, requestType string, err error)
	WriteCallback   func(o *output.ResultEvent)
}

// NewMockOutputWriter creates a new mock output writer
func NewMockOutputWriter() *MockOutputWriter {
	return &MockOutputWriter{aurora: aurora.NewAurora(false)}
}

// Close closes the output writer interface
func (m *MockOutputWriter) Close() {}

// Colorizer returns the colorizer instance for writer
func (m *MockOutputWriter) Colorizer() aurora.Aurora {
	return m.aurora
}

// Write writes the event to file and/or screen.
func (m *MockOutputWriter) Write(result *output.ResultEvent) error {
	if m.WriteCallback != nil {
		m.WriteCallback(result)
	}
	return nil
}

// Request writes a log the requests trace log
func (m *MockOutputWriter) Request(templateID, url, requestType string, err error) {
	if m.RequestCallback != nil {
		m.RequestCallback(templateID, url, requestType, err)
	}
}

// WriteFailure writes the event to file and/or screen.
func (m *MockOutputWriter) WriteFailure(result output.InternalEvent) error {
	return nil
}

type MockProgressClient struct{}

// Stop stops the progress recorder.
func (m *MockProgressClient) Stop() {}

// Init inits the progress bar with initial details for scan
func (m *MockProgressClient) Init(hostCount int64, rulesCount int, requestCount int64) {}

// AddToTotal adds a value to the total request count
func (m *MockProgressClient) AddToTotal(delta int64) {}

// IncrementRequests increments the requests counter by 1.
func (m *MockProgressClient) IncrementRequests() {}

// IncrementMatched increments the matched counter by 1.
func (m *MockProgressClient) IncrementMatched() {}

// IncrementErrorsBy increments the error counter by count.
func (m *MockProgressClient) IncrementErrorsBy(count int64) {}

// IncrementFailedRequestsBy increments the number of requests counter by count
// along with errors.
func (m *MockProgressClient) IncrementFailedRequestsBy(count int64) {}
