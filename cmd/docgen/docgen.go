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
	updateDescriptionKeyName(m)

	schemax, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("Could not marshal jsonschema: %s\n", err)
	}
	schemax = append(schemax, '\n')
	writeToFile(os.Args[2], schemax)
}

// schemaMapKeywords hold a map of names to subschemas.
var schemaMapKeywords = map[string]struct{}{
	"properties":        {},
	"patternProperties": {},
	"$defs":             {},
	"definitions":       {},
	"dependentSchemas":  {},
}

// schemaKeywords hold a single subschema.
var schemaKeywords = map[string]struct{}{
	"items":                 {},
	"additionalProperties":  {},
	"unevaluatedProperties": {},
	"unevaluatedItems":      {},
	"contains":              {},
	"propertyNames":         {},
	"not":                   {},
	"if":                    {},
	"then":                  {},
	"else":                  {},
}

// schemaListKeywords hold a list of subschemas.
var schemaListKeywords = map[string]struct{}{
	"allOf":       {},
	"anyOf":       {},
	"oneOf":       {},
	"prefixItems": {},
}

// updateDescriptionKeyName copies description to markdownDescription on every
// schema node. It walks only schema keywords, so description keys inside
// examples, defaults, enums and consts stay as they are.
func updateDescriptionKeyName(node map[string]interface{}) {
	if v, ok := node["description"]; ok {
		// Keep standard JSON Schema "description" for non-Monaco consumers
		// and also emit Monaco/VS Code "markdownDescription".
		node["markdownDescription"] = v
	}
	for k, v := range node {
		if _, ok := schemaMapKeywords[k]; ok {
			if children, ok := v.(map[string]interface{}); ok {
				for _, child := range children {
					if childMap, ok := child.(map[string]interface{}); ok {
						updateDescriptionKeyName(childMap)
					}
				}
			}
			continue
		}
		if _, ok := schemaKeywords[k]; ok {
			if childMap, ok := v.(map[string]interface{}); ok {
				updateDescriptionKeyName(childMap)
			}
			continue
		}
		if _, ok := schemaListKeywords[k]; ok {
			if children, ok := v.([]interface{}); ok {
				for _, child := range children {
					if childMap, ok := child.(map[string]interface{}); ok {
						updateDescriptionKeyName(childMap)
					}
				}
			}
		}
	}
}
