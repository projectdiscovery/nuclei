package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"reflect"
	"regexp"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	nucleijson "github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

var pathRegex = regexp.MustCompile(`github\.com/projectdiscovery/nuclei/v3/(?:internal|pkg)/(?:.*/)?([A-Za-z.]+)`)

func writeToFile(filename string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Could not create file %s: %s\n", filename, err)
	}
	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(data); err != nil {
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
		BaseSchemaID: jsonschema.ID("https://nuclei.projectdiscovery.io/"),
		Namer: func(t reflect.Type) string {
			if t.Kind() == reflect.Slice {
				return ""
			}
			return t.String()
		},
	}

	jsonschemaData := r.Reflect(&templates.Template{})

	var buf bytes.Buffer
	encoder := nucleijson.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(jsonschemaData); err != nil {
		log.Fatalf("Could not encode JSON schema: %s\n", err)
	}

	schema := pathRegex.ReplaceAllString(buf.String(), "$1")

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(schema), &m); err != nil {
		log.Fatalf("Could not unmarshal jsonschema: %s\n", err)
	}

	// Stable schema identity for editors / tooling.
	m["$id"] = "https://nuclei.projectdiscovery.io/template-schema.json"

	// Enable markdown descriptions in Monaco / VS Code.
	updateDescriptionKeyName("", m)

	schemax, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("Could not marshal jsonschema: %s\n", err)
	}
	schemax = append(schemax, '\n')
	writeToFile(os.Args[2], schemax)
}

// updateDescriptionKeyName recursively renames description -> markdownDescription
// except when description is a property key under "properties".
func updateDescriptionKeyName(parent string, m map[string]interface{}) {
	for k, v := range m {
		if k == "description" && parent != "properties" {
			delete(m, k)
			m["markdownDescription"] = v
		}
		if vMap, ok := v.(map[string]interface{}); ok {
			updateDescriptionKeyName(k, vMap)
		}
		if vSlice, ok := v.([]interface{}); ok {
			for _, item := range vSlice {
				if itemMap, ok := item.(map[string]interface{}); ok {
					updateDescriptionKeyName(k, itemMap)
				}
			}
		}
	}
}
