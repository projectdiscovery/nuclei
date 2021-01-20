// Package transform understands various types of http request decription
// formats and converts them to their normalized form.
package transform

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/transform/curl2go"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
)

// Callback is a callback for a transformed request
type Callback func(*fuzzing.NormalizedRequest)

// Transform transforms the provided file based on extension into a normalized
// request.
func Transform(representation string) (string, error) {
	stat, err := os.Stat(representation)
	if err != nil {
		return "", errors.Wrap(err, "could not stat input")
	}

	file, err := ioutil.TempFile("", "transformed-*")
	if err != nil {
		return "", errors.Wrap(err, "could not create temp file")
	}
	fileName := file.Name()
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	encoder := jsoniter.NewEncoder(writer)
	callback := func(req *fuzzing.NormalizedRequest) {
		encoder.Encode(req)
	}

	if stat.IsDir() {
		err = parseDirectory(representation, callback)
	} else {
		err = parseFile(representation, callback)
	}
	return fileName, err
}

// parseDirectory parses a directory returning all normalized requests.
func parseDirectory(directory string, callback Callback) error {
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if err := parseFile(path, callback); err != nil {
			gologger.Error().Msgf("Could not parse %s: %s\n", path, err)
		}
		return nil
	})
	return err
}

// parseFile parses a file returning all normalized requests.
func parseFile(file string, callback Callback) error {
	var err error
	if strings.HasSuffix(file, ".curl") {
		err = parseCurlRequest(file, callback)
	}
	if strings.HasSuffix(file, ".raw") || strings.HasSuffix(file, ".txt") {
		err = parseCurlRequest(file, callback)
	}
	return err
}

// parseCurlRequest parses a curl request.
func parseCurlRequest(path string, callback func(req *fuzzing.NormalizedRequest)) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	normalized, err := curl2go.Parse(string(data))
	if err != nil {
		return err
	}
	if normalized == nil {
		callback(normalized)
	}
	return nil
}
