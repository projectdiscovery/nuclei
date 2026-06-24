package generators

import (
	maps0 "maps"
	"reflect"
)

// MergeMapsMany merges many maps into a new map
func MergeMapsMany(maps ...interface{}) map[string][]string {
	m := make(map[string][]string)
	for _, gotMap := range maps {
		val := reflect.ValueOf(gotMap)
		if val.Kind() != reflect.Map {
			continue
		}
		appendToSlice := func(key, value string) {
			if values, ok := m[key]; !ok {
				m[key] = []string{value}
			} else {
				m[key] = append(values, value)
			}
		}
		for _, e := range val.MapKeys() {
			v := val.MapIndex(e)
			switch v.Kind() {
			case reflect.Slice, reflect.Array:
				for i := 0; i < v.Len(); i++ {
					appendToSlice(e.String(), v.Index(i).String())
				}
			case reflect.String:
				appendToSlice(e.String(), v.String())
			case reflect.Interface:
				switch data := v.Interface().(type) {
				case string:
					appendToSlice(e.String(), data)
				case []string:
					for _, value := range data {
						appendToSlice(e.String(), value)
					}
				}
			}
		}
	}
	return m
}

// MergeMaps merges multiple maps into a new map.
//
// Use [CopyMap] if you need to copy a single map.
// Use [MergeMapsInto] to merge into an existing map.
func MergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	mapsLen := 0
	for _, m := range maps {
		mapsLen += len(m)
	}

	merged := make(map[string]interface{}, mapsLen)
	for _, m := range maps {
		maps0.Copy(merged, m)
	}

	return merged
}

// CopyMap creates a shallow copy of a single map.
func CopyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	result := make(map[string]interface{}, len(m))
	maps0.Copy(result, m)

	return result
}

// MergeMapsInto copies all entries from src maps into dst (mutating dst).
//
// Use when dst is a fresh map the caller owns and wants to avoid allocation.
func MergeMapsInto(dst map[string]interface{}, srcs ...map[string]interface{}) {
	for _, src := range srcs {
		maps0.Copy(dst, src)
	}
}

// ExpandMapValues converts values from flat string to string slice
func ExpandMapValues(m map[string]string) map[string][]string {
	m1 := make(map[string][]string, len(m))
	for k, v := range m {
		m1[k] = []string{v}
	}

	return m1
}
