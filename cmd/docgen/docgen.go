package main

import (
	"bytes"
	"log"
	"os"
	"reflect"
	"regexp"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

var pathRegex = regexp.MustCompile(`github\.com/projectdiscovery/nuclei/v3/(?:internal|pkg)/(?:.*/)?([A-Za-z.]+)`)

func writeToFile(filename string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Could not create file %s: %s\n", filename, err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		log.Fatalf("Could not write to file %s: %s\n", filename, err)
	}
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("syntax: %s md-docs-file jsonschema-file\n", os.Args[0])
	}

	// Generate YAML documentation
	data, err := templates.GetTemplateDoc().Encode()
	if err != nil {
		log.Fatalf("Could not encode docs: %s\n", err)
	}
	writeToFile(os.Args[1], data)

	// Generate JSON Schema
	r := &jsonschema.Reflector{
		Namer: func(t reflect.Type) string {
			if t.Kind() == reflect.Slice {
				return ""
			}
			return t.String()
		},
	}

	jsonschemaData := r.Reflect(&templates.Template{})

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(jsonschemaData); err != nil {
		log.Fatalf("Could not encode JSON schema: %s\n", err)
	}

	schema := pathRegex.ReplaceAllString(buf.String(), "$1")
	writeToFile(os.Args[2], []byte(schema))
}
