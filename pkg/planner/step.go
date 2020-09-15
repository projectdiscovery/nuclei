package planner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/http"
)

// Step defines a single step to be performed during execution
type Step struct {
	Type       StepType
	HTTP       []*http.CompiledRequest
	DNS        []*dns.CompiledRequest
	Matchers   []*matchers.CompiledMatcher
	Extractors []*matchers.CompiledMatcher

	Next []*Step
}

// StepType is the type of the currently defined step
type StepType int

// Constants representing types of steps
const (
	HTTPStepType StepType = iota
	DNSStepType
	MatchersStepType
	ExtractorsStepType
)
