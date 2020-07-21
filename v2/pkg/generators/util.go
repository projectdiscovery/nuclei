package generators

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadPayloads creating proper data structure
func LoadPayloads(payloads map[string]interface{}) map[string][]string {
	loadedPayloads := make(map[string][]string)
	// load all wordlists
	for name, payload := range payloads {
		switch payload.(type) {
		case string:
			v := payload.(string)
			elements := strings.Split(v, "\n")
			if len(elements) >= 2 {
				loadedPayloads[name] = elements
			} else {
				loadedPayloads[name] = LoadFile(v)
			}
		case []interface{}, interface{}:
			vv := payload.([]interface{})
			var v []string
			for _, vvv := range vv {
				v = append(v, fmt.Sprintf("%v", vvv))
			}
			loadedPayloads[name] = v
		}
	}

	return loadedPayloads
}

// LoadFile into slice of strings
func LoadFile(filepath string) (lines []string) {
	for line := range StreamFile(filepath) {
		lines = append(lines, line)
	}

	return
}

// StreamFile content to a chan
func StreamFile(filepath string) (content chan string) {
	content = make(chan string)

	go func() {
		defer close(content)
		file, err := os.Open(filepath)
		if err != nil {
			return
		}
		defer file.Close()

		// yql filter applied
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			content <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			return
		}
	}()

	return
}

// MergeMaps into a new one
func MergeMaps(m1, m2 map[string]interface{}) (m map[string]interface{}) {
	m = make(map[string]interface{})
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}

	return
}

// MergeMapsWithStrings into a new string one
func MergeMapsWithStrings(m1, m2 map[string]string) (m map[string]string) {
	m = make(map[string]string)
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}

	return
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// CopyMap creates a new copy of an existing map
func CopyMap(originalMap map[string]interface{}) map[string]interface{} {
	newMap := make(map[string]interface{})
	for key, value := range originalMap {
		newMap[key] = value
	}
	return newMap
}

// CopyMapWithDefaultValue creates a new copy of an existing map and set a default value
func CopyMapWithDefaultValue(originalMap map[string][]string, defaultValue interface{}) map[string]interface{} {
	newMap := make(map[string]interface{})
	for key := range originalMap {
		newMap[key] = defaultValue
	}
	return newMap
}

// StringContainsAnyMapItem verifies is a string contains any value of a map
func StringContainsAnyMapItem(m map[string]interface{}, s string) bool {
	for key := range m {
		if strings.Contains(s, key) {
			return true
		}
	}

	return false
}

// TrimDelimiters removes trailing brackets
func TrimDelimiters(s string) string {
	return strings.TrimSuffix(strings.TrimPrefix(s, "{{"), "}}")
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
