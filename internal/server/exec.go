package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gopkg.in/yaml.v2"
)

// proxifyRequest is a request for proxify
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header map[string]string `json:"header"`
		Body   string            `json:"body"`
		Raw    string            `json:"raw"`
	} `json:"request"`
}

func runNucleiWithFuzzingInput(target PostReuestsHandlerRequest, templates []string) ([]output.ResultEvent, error) {
	cmd := exec.Command("nuclei")

	tempFile, err := os.CreateTemp("", "nuclei-fuzz-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %s", err)
	}
	defer os.Remove(tempFile.Name())

	payload := proxifyRequest{
		URL: target.URL,
		Request: struct {
			Header map[string]string `json:"header"`
			Body   string            `json:"body"`
			Raw    string            `json:"raw"`
		}{
			Raw: target.RawHTTP,
		},
	}

	marshalledYaml, err := yaml.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshalling yaml: %s", err)
	}

	if _, err := tempFile.Write(marshalledYaml); err != nil {
		return nil, fmt.Errorf("error writing to temp file: %s", err)
	}

	argsArray := []string{
		"-duc",
		"-dast",
		"-silent",
		"-no-color",
		"-jsonl",
	}
	for _, template := range templates {
		argsArray = append(argsArray, "-t", template)
	}
	argsArray = append(argsArray, "-l", tempFile.Name())
	argsArray = append(argsArray, "-im=yaml")
	cmd.Args = append(cmd.Args, argsArray...)

	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running nuclei: %w", err)
	}

	var nucleiResult []output.ResultEvent
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var result output.ResultEvent
		if err := decoder.Decode(&result); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error decoding nuclei output: %w", err)
		}
		// Filter results with a valid template-id
		if result.TemplateID != "" {
			nucleiResult = append(nucleiResult, result)
		}
	}

	return nucleiResult, nil
}
