package scan

import (
	"context"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

type ScanContext struct {
	context.Context
	Input  *contextargs.Context
	errors []error
	events []*output.InternalWrappedEvent

	OnError  func(error)
	OnResult func(e *output.InternalWrappedEvent)
}

func NewScanContext(input *contextargs.Context) *ScanContext {
	return &ScanContext{Input: input}
}

func (s *ScanContext) GenerateResult() []*output.ResultEvent {
	return aggregateResults(s.events)
}

func aggregateResults(events []*output.InternalWrappedEvent) []*output.ResultEvent {
	var results []*output.ResultEvent
	for _, e := range events {
		results = append(results, e.Results...)
	}
	return results
}

func joinErrors(errors []error) string {
	var errorMessages []string
	for _, e := range errors {
		errorMessages = append(errorMessages, e.Error())
	}
	return strings.Join(errorMessages, "; ")
}

func (s *ScanContext) LogEvent(e *output.InternalWrappedEvent) {
	if s.OnResult != nil {
		s.OnResult(e)
	}
	s.events = append(s.events, e)
}

func (s *ScanContext) LogError(err error) {
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
