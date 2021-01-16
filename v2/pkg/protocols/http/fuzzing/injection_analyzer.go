package fuzzing

// InjectionPoint is a single point in the request which can be injected
// with payloads for scanning the request.
type InjectionPoint struct {
}

// AnalyzerOptions contains configuration options for the injection
// point analyzer.
type AnalyzerOptions struct {
	// FuzzCookies enables fuzzing of cookie value pairs. By default, cookies
	// are not scanned for vulnerabilities.
	FuzzCookies bool
}

// AnalyzeInjections analyzes a normalized request with an analyzer
// configuration and returns all the points where input can be tampered
// or supplied to detect web vulnerabilities.
func AnalyzeInjections(req *NormalizedRequest, options *AnalyzerOptions) {

}
