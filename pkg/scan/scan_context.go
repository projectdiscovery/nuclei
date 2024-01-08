package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

type ScanContext struct {
	context.Context
	// exported / configurable fields
	Input *contextargs.Context

	// callbacks or hooks
	OnError  func(error)
	OnResult func(e *output.InternalWrappedEvent)

	// unexported state fields
	errors   []error
	warnings []string
	events   []*output.InternalWrappedEvent

	// might not be required but better to sync
	m sync.Mutex
}

// NewScanContext creates a new scan context using input
func NewScanContext(input *contextargs.Context) *ScanContext {
	return &ScanContext{Input: input}
}

// GenerateResult returns final results slice from all events
func (s *ScanContext) GenerateResult() []*output.ResultEvent {
	s.m.Lock()
	defer s.m.Unlock()
	return aggregateResults(s.events)
}

// LogEvent logs events to all events and triggeres any callbacks
func (s *ScanContext) LogEvent(e *output.InternalWrappedEvent) {
	s.m.Lock()
	defer s.m.Unlock()
	if e == nil {
		// do not log nil events
		return
	}
	if s.OnResult != nil {
		s.OnResult(e)
	}
	s.events = append(s.events, e)
}

// LogError logs error to all events and triggeres any callbacks
func (s *ScanContext) LogError(err error) {
	s.m.Lock()
	defer s.m.Unlock()
	if err == nil {
		return
	}

	if s.OnError != nil {
		s.OnError(err)
	}
	s.errors = append(s.errors, err)

	errorMessage := joinErrors(s.errors)
	results := aggregateResults(s.events)
	for _, result := range results {
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
	s.warnings = append(s.warnings, val)

	for _, e := range s.events {
		if e.InternalEvent != nil {
			e.InternalEvent["warning"] = strings.Join(s.warnings, "; ")
		}
	}
}

// aggregateResults aggregates results from multiple events
func aggregateResults(events []*output.InternalWrappedEvent) []*output.ResultEvent {
	var results []*output.ResultEvent
	for _, e := range events {
		results = append(results, e.Results...)
	}
	return results
}

// joinErrors joins multiple errors and returns a single error string
func joinErrors(errors []error) string {
	var errorMessages []string
	for _, e := range errors {
		if e != nil {
			errorMessages = append(errorMessages, e.Error())
		}
	}
	return strings.Join(errorMessages, "; ")
}
