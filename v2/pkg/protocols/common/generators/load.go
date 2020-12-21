package generators

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

// loadPayloads loads the input payloads from a map to a data map
func loadPayloads(payloads map[string]interface{}) (map[string][]string, error) {
	loadedPayloads := make(map[string][]string)

	for name, payload := range payloads {
		switch pt := payload.(type) {
		case string:
			elements := strings.Split(pt, "\n")
			//golint:gomnd // this is not a magic number
			if len(elements) >= 2 {
				loadedPayloads[name] = elements
			} else {
				payloads, err := loadPayloadsFromFile(pt)
				if err != nil {
					return nil, errors.Wrap(err, "could not load payloads")
				}
				loadedPayloads[name] = payloads
			}
		case interface{}:
			loadedPayloads[name] = cast.ToStringSlice(pt)
		}
	}
	return loadedPayloads, nil
}

// loadPayloadsFromFile loads a file to a string slice
func loadPayloadsFromFile(filepath string) ([]string, error) {
	var lines []string

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		lines = append(lines, text)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return lines, scanner.Err()
	}
	return lines, nil
}
