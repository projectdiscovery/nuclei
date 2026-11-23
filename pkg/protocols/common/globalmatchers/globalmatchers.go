package globalmatchers

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Storage is a struct that holds the global matchers
type Storage struct {
	requests []*Item
	// operators holds the operators of every item as json, for Reads
	operators []byte
}

// Callback is called when a global matcher is matched.
// It receives internal event & result of the operator execution.
type Callback func(event output.InternalEvent, result *operators.Result)

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
	return &Storage{requests: make([]*Item, 0)}
}

// hasStorage checks if the Storage is initialized
func (s *Storage) hasStorage() bool {
	return s != nil
}

// AddOperator adds a new operator to the global matchers
func (s *Storage) AddOperator(item *Item) {
	if !s.hasStorage() {
		return
	}

	s.requests = append(s.requests, item)
	if data, err := json.Marshal(item.Operators); err == nil {
		s.operators = append(s.operators, data...)
	}
}

// Reads reports whether any global matcher may read one of parts.
func (s *Storage) Reads(parts ...string) bool {
	if !s.hasStorage() {
		return false
	}
	return slices.ContainsFunc(parts, func(part string) bool { return bytes.Contains(s.operators, []byte(part)) })
}

// HasMatchers returns true if we have global matchers
func (s *Storage) HasMatchers() bool {
	if !s.hasStorage() {
		return false
	}

	return len(s.requests) > 0
}

// NeedsResponse returns true if any global matcher operator requires the full response.
func (s *Storage) NeedsResponse() bool {
	if !s.hasStorage() {
		return false
	}
	for _, item := range s.requests {
		for _, operator := range item.Operators {
			if operator.NeedsResponse() {
				return true
			}
		}
	}
	return false
}

// Match matches the global matchers against the response
func (s *Storage) Match(
	event output.InternalEvent,
	matchFunc operators.MatchFunc,
	extractFunc operators.ExtractFunc,
	isDebug bool,
	callback Callback,
) {
	for _, item := range s.requests {
		for _, operator := range item.Operators {
			newEvent := maps.Clone(event)
			newEvent.Set("origin-template-id", event["template-id"])
			newEvent.Set("origin-template-info", event["template-info"])
			newEvent.Set("origin-template-path", event["template-path"])
			newEvent.Set("template-id", item.TemplateID)
			newEvent.Set("template-info", item.TemplateInfo)
			newEvent.Set("template-path", item.TemplatePath)
			newEvent.Set("global-matchers", true)

			result, matched := operator.Execute(newEvent, matchFunc, extractFunc, isDebug)
			if !matched {
				continue
			}

			callback(newEvent, result)
		}
	}
}
