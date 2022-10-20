package inputs

type SimpleInputProvider struct {
	Inputs []string
}

// Count returns the number of items for input provider
func (s *SimpleInputProvider) Count() int64 {
	return int64(len(s.Inputs))
}

// Scan calls a callback function till the input provider is exhausted
func (s *SimpleInputProvider) Scan(callback func(value string) bool) {
	for _, v := range s.Inputs {
		if !callback(v) {
			return
		}
	}
}
