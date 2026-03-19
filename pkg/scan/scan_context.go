package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/honeypot"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
)

type ScanContextOption func(*ScanContext)

func WithEvents() ScanContextOption {
	return func(sc *ScanContext) {
		sc.withEvents = true
	}
}

func WithOptions(opts *types.Options) ScanContextOption {
	return func(sc *ScanContext) {
		sc.options = opts
	}
}

type ScanContext struct {
	ctx context.Context

	// exported / configurable fields
	Input *contextargs.Context

	// callbacks or hooks
	OnError   func(error)
	OnResult  func(e *output.InternalWrappedEvent)
	OnWarning func(string)

	// unexported state fields
	error    error
	warnings []string
	events   []*output.InternalWrappedEvent
	results  []*output.ResultEvent

	// what to log
	withEvents bool

	// scan options
	options *types.Options

	// might not be required but better to sync
	m sync.Mutex
}

// NewScanContext creates a new scan context using input
func NewScanContext(ctx context.Context, input *contextargs.Context) *ScanContext {
	return &ScanContext{ctx: ctx, Input: input}
}

// NewScanContextWithOptions creates a new scan context with options
func NewScanContextWithOptions(ctx context.Context, input *contextargs.Context, options *types.Options) *ScanContext {
	return &ScanContext{ctx: ctx, Input: input, options: options}
}

// Context returns the context of the scan
func (s *ScanContext) Context() context.Context {
	return s.ctx
}

func (s *ScanContext) GenerateErrorMessage() error {
	return s.error
}

// GenerateResult returns final results slice from all events
func (s *ScanContext) GenerateResult() []*output.ResultEvent {
	s.m.Lock()
	defer s.m.Unlock()

	return s.results
}

// LogEvent logs events to all events and triggers any callbacks
func (s *ScanContext) LogEvent(e *output.InternalWrappedEvent) {
	s.m.Lock()
	defer s.m.Unlock()
	if e == nil {
		// do not log nil events
		return
	}

	// Honeypot detection integration
	if s.options != nil && s.options.HoneypotDetectionEnabled {
		for _, result := range e.Results {
			host := result.Host
			if host != "" {
				if honeypot.Record(host, result.TemplateID, s.options) {
					// Mark result as from honeypot
					if result.Metadata == nil {
						result.Metadata = make(map[string]interface{})
					}
					result.Metadata["honeypot"] = true
					result.Metadata["honeypot_match_count"] = honeypot.Count(host)
				}
			}
		}
	}

	if s.OnResult != nil {
		s.OnResult(e)
	}

	if s.withEvents {
		s.events = append(s.events, e)
	}

	e.RLock()
	defer e.RUnlock()

	s.results = append(s.results, e.Results...)
}

// LogError logs error to all events and triggers any callbacks
func (s *ScanContext) LogError(err error) {
	s.m.Lock()
	defer s.m.Unlock()
	if err == nil {
		return
	}
	if s.OnError != nil {
		s.OnError(err)
	}
	if s.error == nil {
		s.error = err
	} else {
		s.error = errkit.Append(s.error, err)
	}

	errorMessage := s.GenerateErrorMessage().Error()

	for _, result := range s.results {
		result.Error = errorMessage
	}

	for _, e := range s.events {
		e.InternalEvent["error"] = errorMessage
	}
}

// LogWarning logs warning to all events
func (s *ScanContext) LogWarning(format string, args ...any) {
	s.m.Lock()
	defer s.m.Unlock()
	val := fmt.Sprintf(format, args...)

	if s.OnWarning != nil {
		s.OnWarning(val)
	}

	s.warnings = append(s.warnings, val)

	for _, e := range s.events {
		if e.InternalEvent != nil {
			e.InternalEvent["warning"] = strings.Join(s.warnings, "; ")
		}
	}
}
