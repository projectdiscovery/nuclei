package dataformat

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	normalizedRegex = `_(\d+)$`
)

var (
	reNormalized = regexp.MustCompile(normalizedRegex)
)

// == Handling Duplicate Query Parameters / Form Data ==
// Nuclei supports fuzzing duplicate query parameters by internally normalizing
// them and denormalizing them back when creating request this normalization
// can be leveraged to specify custom fuzzing behaviour in template as well
// if a query like `?foo=bar&foo=baz&foo=fuzzz` is provided, it will be normalized to
// foo_1=bar , foo_2=baz , foo=fuzzz (i.e last value is given original key which is usual behaviour in HTTP and its implementations)
// this way this change does not break any existing rules in template given by keys-regex or keys
// At same time if user wants to specify 2nd or 1st duplicate value in template, they can use foo_1 or foo_2 in keys-regex or keys
// Note: By default all duplicate query parameters are fuzzed

type Form struct{}

var (
	_ DataFormat = &Form{}
)

// NewForm returns a new Form encoder
func NewForm() *Form {
	return &Form{}
}

// IsType returns true if the data is Form encoded
func (f *Form) IsType(data string) bool {
	return false
}

// Encode encodes the data into Form format
func (f *Form) Encode(data KV) (string, error) {
	params := urlutil.NewOrderedParams()

	data.Iterate(func(key string, value any) bool {
		params.Add(key, fmt.Sprint(value))
		return true
	})

	normalized := map[string]map[string]string{}
	// Normalize the data
	for _, origKey := range data.OrderedMap.GetKeys() {
		// here origKey is base key without _1, _2 etc.
		if origKey != "" && !reNormalized.MatchString(origKey) {
			params.Iterate(func(key string, value []string) bool {
				if strings.HasPrefix(key, origKey) && reNormalized.MatchString(key) {
					m := map[string]string{}
					if normalized[origKey] != nil {
						m = normalized[origKey]
					}
					if len(value) == 1 {
						m[key] = value[0]
					} else {
						m[key] = ""
					}
					normalized[origKey] = m
					params.Del(key)
				}
				return true
			})
		}
	}

	if len(normalized) > 0 {
		for k, v := range normalized {
			maxIndex := -1
			for key := range v {
				matches := reNormalized.FindStringSubmatch(key)
				if len(matches) == 2 {
					dataIdx, err := strconv.Atoi(matches[1])
					if err != nil {
						gologger.Verbose().Msgf("error converting normalized index(%v) to integer: %v", matches[1], err)
						continue
					}
					if dataIdx > maxIndex {
						maxIndex = dataIdx
					}
				}
			}
			if maxIndex >= 0 { // Ensure the slice is only created if maxIndex is valid
				data := make([]string, maxIndex+1) // Ensure the slice is large enough
				for key, value := range v {
					matches := reNormalized.FindStringSubmatch(key)
					if len(matches) == 2 {
						dataIdx, err := strconv.Atoi(matches[1]) // Error already checked above
						if err != nil {
							gologger.Verbose().Msgf("error converting data index to integer: %v", err)
							continue
						}
						// Validate dataIdx to avoid index out of range errors
						if dataIdx > 0 && dataIdx <= len(data) {
							data[dataIdx-1] = value // Use dataIdx-1 since slice is 0-indexed
						} else {
							gologger.Verbose().Msgf("data index out of range: %d", dataIdx)
						}
					}
				}
				if len(params.Get(k)) > 0 {
					data[maxIndex] = fmt.Sprint(params.Get(k)) // Use maxIndex which is the last index
				}
				// remove existing
				params.Del(k)
				if len(data) > 0 {
					params.Add(k, data...)
				}
			}
		}
	}

	encoded := params.Encode()
	return encoded, nil
}

// Decode decodes the data from Form format
func (f *Form) Decode(data string) (KV, error) {
	ordered_params := urlutil.NewOrderedParams()
	ordered_params.Merge(data)

	values := mapsutil.NewOrderedMap[string, any]()
	ordered_params.Iterate(func(key string, value []string) bool {
		if len(value) == 1 {
			values.Set(key, value[0])
		} else {
			// in case of multiple query params in form data
			// last value is considered and previous values are exposed with _1, _2, _3 etc.
			// note that last value will not be included in _1, _2, _3 etc.
			for i := 0; i < len(value)-1; i++ {
				values.Set(key+"_"+strconv.Itoa(i+1), value[i])
			}
			values.Set(key, value[len(value)-1])
		}
		return true
	})
	return KVOrderedMap(&values), nil
}

// Name returns the name of the encoder
func (f *Form) Name() string {
	return FormDataFormat
}
