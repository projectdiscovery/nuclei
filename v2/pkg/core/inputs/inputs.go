package inputs

import "github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"

type SimpleInputProvider struct {
	Inputs []*contextargs.MetaInput
}

// Count returns the number of items for input provider
func (s *SimpleInputProvider) Count() int64 {
	return int64(len(s.Inputs))
}

// Scan calls a callback function till the input provider is exhausted
func (s *SimpleInputProvider) Scan(callback func(value *contextargs.MetaInput)) {
	for _, v := range s.Inputs {
		callback(v)
	}
}
