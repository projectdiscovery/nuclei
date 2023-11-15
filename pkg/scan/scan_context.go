package scan

import (
	"context"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

type ScanContext struct {
	context.Context
	ScanId string // MD5 (templateID+target+ip)
	// existing Input/target related info
	Input *contextargs.Context
	// templateInfo
	Info model.Info
	// Globally shared args aka template Context
	TemplateMap map[string]interface{}
	// stats tracker like req count etc
	// Stats *Stats

	errors  []error
	results []*output.ResultEvent

	OnError  func(error)
	OnResult func(e *output.InternalWrappedEvent)
}

func NewScanContext(input *contextargs.Context) *ScanContext {
	return &ScanContext{Input: input}
}

func (s *ScanContext) GenerateResult() []*output.ResultEvent {
	// ...
	return s.results
}

func (s *ScanContext) LogEvent(e *output.InternalWrappedEvent) {
	if s.OnResult != nil {
		s.OnResult(e)
	}
	s.results = append(s.results, e.Results...)
}

func (s *ScanContext) LogError(err error) error {
	if s.OnError != nil {
		s.OnError(err)
	}
	s.errors = append(s.errors, err)
	return err
}
