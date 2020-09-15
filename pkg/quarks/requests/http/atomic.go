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
	AtomicRequests    []AtomicRequest
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
	method       string
	redirects    int
	maxRedirects int
	path         string
	headers      map[string]string
	body         string

	matchers   []matchers.CompiledMatcher
	extractors []extractors.CompiledExtractor
}

// Compare checks if an atomic request is exactly same as the other request.
func (a *AtomicRequest) Compare(req *AtomicRequest) bool {
	if !strings.EqualFold(a.method, req.method) {
		return false
	}
	if a.redirects != req.redirects || a.maxRedirects != req.maxRedirects {
		return false
	}
	if !strings.EqualFold(a.path, req.path) {
		return false
	}
	if !reflect.DeepEqual(a.headers, req.headers) {
		return false
	}
	if len(a.body) != len(req.body) || a.body != req.body {
		return false
	}
	return true
}
