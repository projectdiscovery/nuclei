package generators

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cast"
)

// loadPayloads loads the input payloads from a map to a data map
func (generator *PayloadGenerator) loadPayloads(payloads map[string]interface{}, templatePath, templateDirectory, noise string, sandbox bool) (map[string][]string, error) {
	loadedPayloads := make(map[string][]string)

	for name, payload := range payloads {
		switch pt := payload.(type) {
		case string:
			elements := strings.Split(pt, "\n")
			//golint:gomnd // this is not a magic number
			if len(elements) >= 2 {
				loadedPayloads[name] = elements
			} else {
				if sandbox {
					pt = filepath.Clean(pt)
					templatePathDir := filepath.Dir(templatePath)
					if !(templatePathDir != "/" && strings.HasPrefix(pt, templatePathDir)) && !strings.HasPrefix(pt, templateDirectory) {
						return nil, errors.New("denied payload file path specified")
					}
				}
				payloads, err := generator.loadPayloadsFromFile(pt)
				if err != nil {
					return nil, errors.Wrap(err, "could not load payloads")
				}
				loadedPayloads[name] = payloads
			}
		case map[interface{}]interface{}:
			if noise == "" {
				return nil, errors.New("noise payloads cannot be used without fuzzing")
			}
			noiseValues, err := convertMapInterfaceToNoiseMapping(pt)
			if err != nil {
				return nil, err
			}
			switch strings.ToLower(noise) {
			case "low":
				loadedPayloads[name] = noiseValues.low
			case "medium":
				loadedPayloads[name] = append(noiseValues.low, noiseValues.medium...)
			case "high":
				medium := append(noiseValues.low, noiseValues.medium...)
				loadedPayloads[name] = append(medium, noiseValues.high...)
			}
		case interface{}:
			loadedPayloads[name] = cast.ToStringSlice(pt)
		}
	}
	return loadedPayloads, nil
}

type noiseToPayloads struct {
	low    []string
	medium []string
	high   []string
}

func convertMapInterfaceToNoiseMapping(slice map[interface{}]interface{}) (*noiseToPayloads, error) {
	s := &noiseToPayloads{}
	for k, v := range slice {
		key, ok := k.(string)
		if !ok {
			return nil, errors.Errorf("invalid type specified for key: %v", k)
		}
		values := cast.ToStringSlice(v)
		if len(values) == 0 {
			return nil, errors.Errorf("invalid blank payload set specified: %s", key)
		}
		switch strings.ToLower(key) {
		case "low":
			s.low = values
		case "medium":
			s.medium = values
		case "high":
			s.high = values
		}
	}
	if len(s.low) == 0 || len(s.medium) == 0 || len(s.high) == 0 {
		return nil, errors.Errorf("invalid noise payload set: %v", slice)
	}
	return s, nil
}

// loadPayloadsFromFile loads a file to a string slice
func (generator *PayloadGenerator) loadPayloadsFromFile(filepath string) ([]string, error) {
	var lines []string

	file, err := generator.catalog.OpenFile(filepath)
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
