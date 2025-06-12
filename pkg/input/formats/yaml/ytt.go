package yaml

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	yttcmd "carvel.dev/ytt/pkg/cmd/template"
	yttui "carvel.dev/ytt/pkg/cmd/ui"
	yttfiles "carvel.dev/ytt/pkg/files"
	"gopkg.in/yaml.v2"
)

func ytt(tpl, dvs []string) (io.Reader, error) {
	// create and invoke ytt "template" command
	templatingOptions := yttcmd.NewOptions()

	input, err := templatesAsInput(tpl...)
	if err != nil {
		return nil, err
	}

	// equivalent to `--data-value-yaml`
	templatingOptions.DataValuesFlags.KVsFromYAML = dvs

	// for in-memory use, pipe output to "/dev/null"
	noopUI := yttui.NewCustomWriterTTY(false, noopWriter{}, noopWriter{})

	// Evaluate the template given the configured data values...
	output := templatingOptions.RunWithFiles(input, noopUI)
	if output.Err != nil {
		return nil, output.Err
	}

	// output.DocSet contains the full set of resulting YAML documents, in order.
	bs, err := output.DocSet.AsBytes()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(bs), nil
}

// templatesAsInput conveniently wraps one or more strings, each in a files.File, into a template.Input.
func templatesAsInput(tpl ...string) (yttcmd.Input, error) {
	var files []*yttfiles.File
	for i, t := range tpl {
		// to make this less brittle, you'll probably want to use well-defined names for `path`, here, for each input.
		// this matters when you're processing errors which report based on these paths.
		file, err := yttfiles.NewFileFromSource(yttfiles.NewBytesSource(fmt.Sprintf("tpl%d.yml", i), []byte(t)))
		if err != nil {
			return yttcmd.Input{}, err
		}

		files = append(files, file)
	}

	return yttcmd.Input{Files: files}, nil
}

func mapToKeyValueSlice(m map[string]interface{}) []string {
	var result []string
	for k, v := range m {
		y, _ := yaml.Marshal(v)
		result = append(result, fmt.Sprintf("%s=%s", k, strings.TrimSpace(string(y))))
	}
	return result
}

type noopWriter struct{}

func (w noopWriter) Write(data []byte) (int, error) { return len(data), nil }
