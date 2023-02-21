package templates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestTemplateStruct(t *testing.T) {
	// Unit test to check/validate template Marshal/Unmarshal
	// load a test template
	home, _ := os.UserHomeDir()
	templatePath := filepath.Join(home, "nuclei-templates", "fuzzing/valid-gmail-check.yaml")
	bin, err := os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	var yamlTemplate Template
	err = yaml.Unmarshal(bin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
	jsonBin, err := json.Marshal(yamlTemplate)
	require.Nil(t, err, "failed to marshal template to json")
	var jsonTemplate Template
	err = json.Unmarshal(jsonBin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")
}
