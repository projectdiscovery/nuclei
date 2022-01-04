package generators

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

// PayloadLoader is an interface implemented by payload loaders
type PayloadLoader interface {
	Load(name string) ([]string, error)
}

var DefaultLoader PayloadLoader = &FilePayloadLoader{}

// FilePayloadLoader implementes loading of payload from file
type FilePayloadLoader struct{}

// Load loads payloads from a file for a given name
func (f *FilePayloadLoader) Load(name string) ([]string, error) {
	var lines []string

	file, err := os.Open(name)
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
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return lines, scanner.Err()
	}
	return lines, nil
}

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
				payloads, err := DefaultLoader.Load(pt)
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
