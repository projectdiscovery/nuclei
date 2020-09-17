package http

// Compile returns the compiled version of a request
func (r *Request) Compile() (*CompiledRequest, error) {
	// Process the raw requests differently than normal requests.
	if len(r.Raw) > 0 {
		return r.compileRawRequests()
	}
	return nil, nil
}
