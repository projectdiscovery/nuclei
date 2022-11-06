package generators

import stringsutil "github.com/projectdiscovery/utils/strings"

// SliceToMap converts a slice of strings to map of string splitting each item at sep as "key sep value"
func SliceToMap(s []string, sep string) map[string]interface{} {
	m := make(map[string]interface{})
	for _, sliceItem := range s {
		key, _ := stringsutil.Before(sliceItem, sep)
		value, _ := stringsutil.After(sliceItem, sep)
		if key != "" {
			m[key] = value
		}
	}
	return m
}
