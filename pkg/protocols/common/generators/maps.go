package generators

import (
	maps0 "maps"
	"reflect"
)

// MergeMapsMany merges many maps into a new map.
//
// Fast paths handle the two map shapes the codebase actually passes:
// map[string][]string and map[string]interface{}. Other shapes fall back to
// the reflect-based implementation. This avoids per-key reflect.Value
// allocation on the HTTP operator-callback hot path
// (pkg/protocols/http/request.go) which fires on every successful response.
func MergeMapsMany(maps ...interface{}) map[string][]string {
	m := make(map[string][]string)
	appendToSlice := func(key, value string) {
		m[key] = append(m[key], value)
	}
	for _, gotMap := range maps {
		switch typed := gotMap.(type) {
		case map[string][]string:
			for k, vs := range typed {
				m[k] = append(m[k], vs...)
			}
		case map[string]interface{}:
			for k, v := range typed {
				switch data := v.(type) {
				case string:
					appendToSlice(k, data)
				case []string:
					for _, value := range data {
						appendToSlice(k, value)
					}
				}
			}
		case map[string]string:
			for k, v := range typed {
				appendToSlice(k, v)
			}
		default:
			mergeMapsManyReflect(m, gotMap, appendToSlice)
		}
	}
	return m
}

func mergeMapsManyReflect(m map[string][]string, gotMap interface{}, appendToSlice func(string, string)) {
	val := reflect.ValueOf(gotMap)
	if val.Kind() != reflect.Map {
		return
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
