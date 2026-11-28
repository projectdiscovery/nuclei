package http

// PipelineAddress exports pipelineAddress to the tests of package http_test.
func PipelineAddress(requestURL string) string {
	return pipelineAddress(requestURL)
}
