package http

import (
	"reflect"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
)

// CompiledRequest is the compiled http request structure created
// by parsing and processing the data from read file.
type CompiledRequest struct {
	AtomicRequests    []*AtomicRequest
	RequestsCondition Condition
}

// Condition is the type of condition for matcher
type Condition int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition Condition = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// Conditions is an table for conversion of condition type from string.
var Conditions = map[string]Condition{
	"and": ANDCondition,
	"or":  ORCondition,
}

// AtomicRequest is a single atomic http request sent to a server
type AtomicRequest struct {
	Method       string
	Redirects    int
	MaxRedirects int
	Path         string
	Headers      map[string]string
	Body         string

	Matchers   []*matchers.CompiledMatcher
	Extractors []*extractors.CompiledExtractor
}

// Compare checks if an atomic request is exactly same as the other request.
func (a *AtomicRequest) Compare(req *AtomicRequest) bool {
	if !strings.EqualFold(a.Method, req.Method) {
		return false
	}
	if a.Redirects != req.Redirects || a.MaxRedirects != req.MaxRedirects {
		return false
	}
	if !strings.EqualFold(a.Path, req.Path) {
		return false
	}
	if !reflect.DeepEqual(a.Headers, req.Headers) {
		return false
	}
	if len(a.Body) != len(req.Body) || a.Body != req.Body {
		return false
	}
	return true
}
