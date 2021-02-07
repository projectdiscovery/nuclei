// Package transform understands various types of http request decription
// formats and converts them to their normalized form.
package transform

import (
	"bufio"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/transform/burpxml"
	"github.com/projectdiscovery/nuclei/v2/internal/transform/curl2go"
	"github.com/projectdiscovery/nuclei/v2/internal/transform/raw"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/fuzzing"
)

// Callback is a callback for a transformed request
type Callback func(*fuzzing.NormalizedRequest)

// Transform transforms the provided file based on extension into a normalized
// request file.
func Transform(representation string) (string, error) {
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
	stat, err := os.Stat(representation)
	if err != nil {
		return "", err
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
	if strings.HasSuffix(file, ".curl") {
		return parseCurlRequest(file, callback)
	}
	if strings.HasSuffix(file, ".raw") || strings.HasSuffix(file, ".txt") {
		return parseRawRequest(file, callback)
	}
	if strings.HasSuffix(file, ".xml") || strings.HasSuffix(file, ".burp") {
		return parseBurpRequests(file, callback)
	}
	if strings.HasSuffix(file, ".json") {
		return parseNormalizedRequests(file, callback)
	}
	return nil
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

	if normalized != nil {
		callback(normalized)
	}
	return nil
}

// parseRawRequest parses a raw request.
func parseRawRequest(path string, callback func(req *fuzzing.NormalizedRequest)) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	normalized, err := raw.Parse(string(data), "http://test.com")
	if err != nil {
		return err
	}
	if normalized != nil {
		callback(normalized)
	}
	return nil
}

// parseBurpRequests parses burp suite xml request export.
func parseBurpRequests(path string, callback func(req *fuzzing.NormalizedRequest)) error {
	err := burpxml.Parse(path, callback)
	return err
}

// parseNormalizedRequests parses normalized nuclei request export.
func parseNormalizedRequests(path string, callback func(req *fuzzing.NormalizedRequest)) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "could not open file")
	}
	defer file.Close()

	normalized := &fuzzing.NormalizedRequest{}
	decoder := jsoniter.ConfigCompatibleWithStandardLibrary.NewDecoder(file)
	for {
		err := decoder.Decode(normalized)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		callback(normalized)
	}
	return nil
}
