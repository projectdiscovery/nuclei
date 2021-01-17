package fuzzing

// InjectionPoint is a single point in the request which can be injected
// with payloads for scanning the request.
type InjectionPoint struct {
}

// AnalyzerOptions contains configuration options for the injection
// point analyzer.
type AnalyzerOptions struct {
	// Parts is the list of parts to fuzz for the request.
	//
	// Valid value mappings are -
	//
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
	PartsConfig map[string]*AnalyzerPartsConfig `yaml:"parts-config"`
}

// AnalyzerPartsConfig contains the configuration for a part analyzer.
type AnalyzerPartsConfig struct {
	// Valid is a matcher for valid analyzer keys and values.
	Valid *AnalyerPartsConfigMatcher `yaml:"valid"`
	// Invalid is a matcher for invalid analyzer keys and values.
	Invalid *AnalyerPartsConfigMatcher `yaml:"invalid"`
}

// AnalyerPartsConfigMatcher is a single matcher for an analyzer configuration
type AnalyerPartsConfigMatcher struct {
	// Exact enables exact matching of parts configuration strings.
	Exact bool `yaml:"exact"`
	// KeysRegex contains a list of regex for key names
	KeysRegex []string `yaml:"keys-regex"`
	// ValuesRegex contains a list of regex for values
	ValuesRegex []string `yam:"values-regex"`
	// Keys contains a list of regex for key name strings.
	Keys []string `yaml:"keys"`
	// Values contains a list of regex for value strings.
	Values []string `yam:"values"`
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
func AnalyzeRequest(req *NormalizedRequest, options *AnalyzerOptions) {

}
