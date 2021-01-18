package fuzzing

import "regexp"

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
	KeysRegex    []string `yaml:"keys-regex"`
	KeysCompiled []*regexp.Regexp
	// ValuesRegex contains a list of regex for values
	ValuesRegex    []string `yam:"values-regex"`
	ValuesCompiled []*regexp.Regexp
	// Keys contains a list of regex for key name strings.
	Keys []string `yaml:"keys"`
	// Values contains a list of regex for value strings.
	Values []string `yam:"values"`
}

// Compile compiles regex, etc for an analyzer configuration
func (a *AnalyzerOptions) Compile() error {
	for _, part := range a.PartsConfig {
		for _, v := range part {
			for _, regex := range v.Valid.KeysRegex {
				regexp, err := regexp.Compile(regex)
				if err != nil {
					return err
				}
				v.Valid.KeysCompiled = append(v.Valid.KeysCompiled, regexp)
			}
			for _, regex := range v.Valid.ValuesRegex {
				regexp, err := regexp.Compile(regex)
				if err != nil {
					return err
				}
				v.Valid.KeysCompiled = append(v.Valid.KeysCompiled, regexp)
			}
			for _, regex := range v.Invalid.KeysRegex {
				regexp, err := regexp.Compile(regex)
				if err != nil {
					return err
				}
				v.Invalid.KeysCompiled = append(v.Invalid.KeysCompiled, regexp)
			}
			for _, regex := range v.Invalid.ValuesRegex {
				regexp, err := regexp.Compile(regex)
				if err != nil {
					return err
				}
				v.Invalid.KeysCompiled = append(v.Invalid.KeysCompiled, regexp)
			}
		}
	}
	return nil
}
