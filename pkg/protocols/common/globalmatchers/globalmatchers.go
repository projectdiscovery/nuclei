package globalmatchers

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"golang.org/x/exp/maps"
)

// Storage is a struct that holds the global matchers
type Storage struct {
	requests []*Item
}

// Item is a struct that holds the global matchers
// details for a template
type Item struct {
	TemplateID   string
	TemplatePath string
	TemplateInfo model.Info
	Operators    []*operators.Operators
}

// New creates a new storage for global matchers
func New() *Storage {
	return &Storage{}
}

// AddOperator adds a new operator to the global matchers
func (s *Storage) AddOperator(item *Item) {
	s.requests = append(s.requests, item)
}

// HasMatchers returns true if we have global matchers
func (s *Storage) HasMatchers() bool {
	return len(s.requests) > 0
}

// Match matches the global matchers against the response
func (s *Storage) Match(
	event output.InternalEvent,
	matchFunc operators.MatchFunc,
	extractFunc operators.ExtractFunc,
	isDebug bool,
	callback func(event output.InternalEvent, result *operators.Result),
) {
	for _, item := range s.requests {
		for _, operator := range item.Operators {
			result, matched := operator.Execute(event, matchFunc, extractFunc, isDebug)
			if !matched {
				continue
			}

			eventCopy := maps.Clone(event)
			eventCopy["template-id"] = item.TemplateID
			eventCopy["template-info"] = item.TemplateInfo
			eventCopy["template-path"] = item.TemplatePath
			eventCopy["passive"] = true
			callback(eventCopy, result)
		}
	}
}
