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
		switch pt := payload.(type) {
		case string:
			elements := strings.Split(pt, "\n")
			if len(elements) >= two {
				loadedPayloads[name] = elements
			} else {
				loadedPayloads[name] = LoadFile(pt)
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
