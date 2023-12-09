package inputs

import (
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

// InputProvider is an input providing interface for the nuclei execution
// engine.
//
// An example InputProvider implementation is provided in form of hybrid
// input provider in pkg/core/inputs/hybrid/hmap.go
type InputProvider interface {
	// Count returns the number of items for input provider
	Count() int64
	// Scan iterates the input and each found item is passed to the
	// callback consumer.
	Scan(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
}

type SimpleInputProvider struct {
	Inputs []*contextargs.MetaInput
}

// Count returns the number of items for input provider
func (s *SimpleInputProvider) Count() int64 {
	return int64(len(s.Inputs))
}

// Scan calls a callback function till the input provider is exhausted
func (s *SimpleInputProvider) Scan(callback func(value *contextargs.MetaInput) bool) {
	for _, v := range s.Inputs {
		if !callback(v) {
			return
		}
	}
}

// Set adds item to input provider
func (s *SimpleInputProvider) Set(value string) {
	s.Inputs = append(s.Inputs, &contextargs.MetaInput{Input: value})
}

// SetWithProbe adds item to input provider with http probing
func (s *SimpleInputProvider) SetWithProbe(value string, httpxClient *httpx.HTTPX) {
	valueToAppend := value
	if result := utils.ProbeURL(value, httpxClient); result != "" {
		valueToAppend = result
	}
	s.Inputs = append(s.Inputs, &contextargs.MetaInput{Input: valueToAppend})
}
