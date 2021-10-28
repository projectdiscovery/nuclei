package testutils

import (
	"go.uber.org/ratelimit"

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
	Metrics:            false,
	Debug:              false,
	DebugRequests:      false,
	DebugResponse:      false,
	Silent:             false,
	Version:            false,
	Verbose:            false,
	NoColor:            true,
	UpdateTemplates:    false,
	JSON:               false,
	JSONRequests:       false,
	EnableProgressBar:  false,
	TemplatesVersion:   false,
	TemplateList:       false,
	Stdin:              false,
	StopAtFirstMatch:   false,
	NoMeta:             false,
	Project:            false,
	MetricsPort:        0,
	BulkSize:           25,
	TemplateThreads:    10,
	Timeout:            5,
	Retries:            1,
	RateLimit:          150,
	ProjectPath:        "",
	Severities:         severity.Severities{},
	Targets:            []string{},
	TargetsFilePath:    "",
	Output:             "",
	ProxyURL:           "",
	ProxySocksURL:      "",
	TemplatesDirectory: "",
	TraceLogFile:       "",
	Templates:          []string{},
	ExcludedTemplates:  []string{},
	CustomHeaders:      []string{},
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
		Output:       output.NewMockOutputWriter(),
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
