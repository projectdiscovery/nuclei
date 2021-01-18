package fuzzing

import "net/http"

// AnalyzerOptions contains configuration options for the injection
// point analyzer.
type AnalyzerOptions struct {
	// Append appends a value to the value for a key found during analysis.
	//
	// Append is most commonly used to preserve old data and add payloads at the
	// end of the old data marker.
	Append []string `yaml:"append"`

	// Replace replaces a value for a key found during analysis.
	//
	// Replace is most commonly used to replace old data with completely new data.
	Replace []string `yaml:"replace"`

	// Parts is the list of parts to fuzz for the request.
	//
	// Valid value mappings are -
	//   default =>  everything except the path and cookies will be fuzzed. (optimal)
	//    If no values are provided, parts are assumed to be default by the engine.
	//    Providing any other part overrides the default part and enables honouring of those
	//    other part values.
	//
	//   path, cookies, body, query-values, headers => self explanatory.
	//
	//   all => All enables fuzzing of all request parts.
	Parts []string `yaml:"parts"`

	// PartsConfig contains a map of configuration for various
	// analysis parts. This configuration will be used to customize
	// the process of fuzzing these part values.
	//
	// Keys are the values provided by the parts field of the configuration.
	// Values contains configuration options for choosing the said part.
	PartsConfig map[string][]*AnalyzerPartsConfig `yaml:"parts-config"`
}

// AnalyzeRequest analyzes a normalized request with an analyzer
// configuration and returns all the points where input can be tampered
// or supplied to detect web vulnerabilities.
//
// Parts are fuzzed on the basis of key value pairs. Various parts of the request
// form iterators which can be then iterated on the basis of key-value pairs.
// First validation is performed by the parts-config value of configuration to
// choose whether this field can be fuzzed or not. If the part can be fuzzed, testing
// is finally performed for the request.
func AnalyzeRequest(req *NormalizedRequest, options *AnalyzerOptions, callback func(*http.Request)) error {
	parts := make(map[string]struct{})

	if len(options.Parts) == 0 {
		parts["default"] = struct{}{}
	} else {
		for _, part := range options.Parts {
			parts[part] = struct{}{}
		}
	}
	if _, ok := parts["default"]; ok {
		parts["body"] = struct{}{}
		parts["query-values"] = struct{}{}
		parts["headers"] = struct{}{}
		delete(parts, "default")
	}
	if _, ok := parts["all"]; ok {
		parts["path"] = struct{}{}
		parts["cookies"] = struct{}{}
		parts["body"] = struct{}{}
		parts["query-values"] = struct{}{}
		parts["headers"] = struct{}{}
		delete(parts, "all")
	}

	if len(options.PartsConfig) == 0 {
		options.PartsConfig = defaultPartsConfig
	}
	return nil
}
