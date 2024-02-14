package provider

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrNotImplemented = errorutil.NewWithFmt("provider %s does not implement %s")
	ErrInactiveInput  = fmt.Errorf("input is inactive")
)

// IsErrNotImplemented checks if an error is a not implemented error
func IsErrNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "provider") && strings.Contains(err.Error(), "does not implement") {
		return true
	}
	return false
}

// InputLivenessProbe is an interface for probing the liveness of an input
type InputLivenessProbe interface {
	// ProbeURL probes the scheme for a URL. first HTTPS is tried
	ProbeURL(input string) (string, error)
}

// InputProvider is an input providing interface for the nuclei execution
// engine.
//
// An example InputProvider implementation is provided in form of hybrid
// input provider in pkg/core/inputs/hybrid/hmap.go
type InputProvider interface {
	// Count returns total targets for input provider
	Count() int64
	// Iterate over all inputs in order
	Iterate(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
	// SetWithProbe adds item to input provider with http probing
	SetWithProbe(value string, probe InputLivenessProbe) error
	// SetWithExclusions adds item to input provider if it doesn't match any of the exclusions
	SetWithExclusions(value string) error
	// InputType returns the type of input provider
	InputType() string
}
