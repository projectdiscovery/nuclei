package generators

import "github.com/projectdiscovery/stringsutil"

// SliceToMap converts a slice of strings to map of string splitting each item at sep as "key sep value"
func SliceToMap(s []string, sep string) map[string]interface{} {
	m := make(map[string]interface{})
	for _, sliceItem := range s {
		key := stringsutil.Before(sliceItem, sep)
		value := stringsutil.After(sliceItem, sep)
		if key != "" {
			m[key] = value
		}
	}
	return m
}
