package fuzzing

import (
	"regexp"
	"strings"
)

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

// Match performs a match on a part config and returns true if the key-value pair
// provided is valid.
func (a *AnalyzerPartsConfig) Match(key string, value string) bool {
	if a.Valid != nil {
		if a.Valid.Match(key, value) {
			return true
		}
		return false
	}
	if a.Invalid != nil {
		if a.Invalid.Match(key, value) {
			return false
		}
		return true
	}
	return true
}

// Match returns true if a config matcher is valid for key value pair.
func (a *AnalyerPartsConfigMatcher) Match(key string, value string) bool {
	for _, regex := range a.KeysCompiled {
		if regex.MatchString(key) {
			return true
		}
	}
	for _, v := range a.Keys {
		if a.Exact && strings.EqualFold(key, v) {
			return true
		} else if !a.Exact && strings.Contains(key, v) {
			return true
		}
	}
	for _, regex := range a.ValuesCompiled {
		if regex.MatchString(value) {
			return true
		}
	}
	for _, v := range a.Values {
		if a.Exact && strings.EqualFold(value, v) {
			return true
		} else if !a.Exact && strings.Contains(key, v) {
			return true
		}
	}
	return false
}
