package testutils

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
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
	Verbose:                    false,
	NoColor:                    true,
	UpdateTemplates:            false,
	JSONL:                      false,
	OmitRawRequests:            false,
	EnableProgressBar:          false,
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
	TraceLogFile:               "",
	Templates:                  []string{},
	ExcludedTemplates:          []string{},
	CustomHeaders:              []string{},
	InteractshURL:              "https://oast.fun",
	InteractionsCacheSize:      5000,
	InteractionsEviction:       60,
	InteractionsCoolDownPeriod: 5,
	InteractionsPollDuration:   5,
	GitHubTemplateRepo:         []string{},
	GitHubToken:                "",
}

// TemplateInfo contains info for a mock executed template.
type TemplateInfo struct {
	ID   string
	Info model.Info
	Path string
}

// NewMockExecuterOptions creates a new mock executeroptions struct
func NewMockExecuterOptions(options *types.Options, info *TemplateInfo) *protocols.ExecutorOptions {
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, false, 0)
	executerOpts := &protocols.ExecutorOptions{
		TemplateID:   info.ID,
		TemplateInfo: info.Info,
		TemplatePath: info.Path,
		Output:       NewMockOutputWriter(),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
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
func (m *MockOutputWriter) WriteFailure(wrappedEvent *output.InternalWrappedEvent) error {
	if m.WriteCallback != nil {
		// create event
		event := wrappedEvent.InternalEvent
		templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]), types.ToString(event["template-id"]))
		var templateInfo model.Info
		if ti, ok := event["template-info"].(model.Info); ok {
			templateInfo = ti
		}
		data := &output.ResultEvent{
			Template:      templatePath,
			TemplateURL:   templateURL,
			TemplateID:    types.ToString(event["template-id"]),
			TemplatePath:  types.ToString(event["template-path"]),
			Info:          templateInfo,
			Type:          types.ToString(event["type"]),
			Host:          types.ToString(event["host"]),
			Request:       types.ToString(event["request"]),
			Response:      types.ToString(event["response"]),
			MatcherStatus: false,
			Timestamp:     time.Now(),
		}
		m.WriteCallback(data)
	}
	return nil
}
func (m *MockOutputWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {

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

// SetRequests sets the counter by incrementing it with a delta
func (m *MockProgressClient) SetRequests(count uint64) {}

// IncrementMatched increments the matched counter by 1.
func (m *MockProgressClient) IncrementMatched() {}

// IncrementErrorsBy increments the error counter by count.
func (m *MockProgressClient) IncrementErrorsBy(count int64) {}

// IncrementFailedRequestsBy increments the number of requests counter by count
// along with errors.
func (m *MockProgressClient) IncrementFailedRequestsBy(count int64) {}
