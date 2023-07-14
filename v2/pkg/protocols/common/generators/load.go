package generators

import (
	"bufio"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	pkgTypes "github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/spf13/cast"
)

// loadPayloads loads the input payloads from a map to a data map
func (generator *PayloadGenerator) loadPayloads(payloads map[string]interface{}, templatePath, templateDirectory string, allowLocalFileAccess bool) (map[string][]string, error) {
	loadedPayloads := make(map[string][]string)

	for name, payload := range payloads {
		switch pt := payload.(type) {
		case string:
			elements := strings.Split(pt, "\n")
			//golint:gomnd // this is not a magic number
			if len(elements) >= 2 {
				loadedPayloads[name] = elements
			} else {
				if !allowLocalFileAccess {
					pt = filepath.Clean(pt)
					templateAbsPath, err := filepath.Abs(templatePath)
					if err != nil {
						return nil, errors.Wrap(err, "could not get absolute path")
					}
					templatePathDir := filepath.Dir(templateAbsPath)
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
		case interface{}:
			loadedPayloads[name] = cast.ToStringSlice(pt)
		}
	}
	return loadedPayloads, nil
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
	if err := scanner.Err(); err != nil && !errors.Is(err, pkgTypes.ErrNoMoreRequests) {
		return lines, scanner.Err()
	}
	return lines, nil
}
