package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

var pathRegex = regexp.MustCompile(`github\.com/projectdiscovery/nuclei/v3/(?:internal|pkg)/(?:.*/)?([A-Za-z.]+)`)

func main() {
	// Generate yaml syntax documentation
	data, err := templates.GetTemplateDoc().Encode()
	if err != nil {
		log.Fatalf("Could not encode docs: %s\n", err)
	}

	if len(os.Args) < 3 {
		log.Fatalf("syntax: %s md-docs-file jsonschema-file\n", os.Args[0])
	}

	err = os.WriteFile(os.Args[1], data, 0644)
	if err != nil {
		log.Fatalf("Could not write docs: %s\n", err)
	}

	// Generate jsonschema
	r := &jsonschema.Reflector{
		BaseSchemaID: jsonschema.ID("https://nuclei.projectdiscovery.io/"),
	}
	jsonschemaData := r.Reflect(&templates.Template{})

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(jsonschemaData)

	schema := buf.String()
	for _, match := range pathRegex.FindAllStringSubmatch(schema, -1) {
		schema = strings.ReplaceAll(schema, match[0], match[1])
	}
	var m map[string]interface{}
	err = json.Unmarshal([]byte(schema), &m)
	if err != nil {
		log.Fatalf("Could not unmarshal jsonschema: %s\n", err)
	}

	// patch the schema to enable markdown Descriptions in monaco and vscode
	updateDescriptionKeyName("", m)

	schemax, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("Could not marshal jsonschema: %s\n", err)
	}
	schema = string(schemax)

	err = os.WriteFile(os.Args[2], []byte(schema), 0644)
	if err != nil {
		log.Fatalf("Could not write jsonschema: %s\n", err)
	}
}

// will recursively find and replace/rename PropName in description
func updateDescriptionKeyName(parent string, m map[string]interface{}) {
	for k, v := range m {
		if k == "description" && parent != "properties" {
			delete(m, k)
			m["markdownDescription"] = v
		}
		// if v is of type object then recursively call this function
		if vMap, ok := v.(map[string]interface{}); ok {
			updateDescriptionKeyName(k, vMap)
		}
	}
}
