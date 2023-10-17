package templates

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestTemplateStruct(t *testing.T) {
	templatePath := "./tests/match-1.yaml"
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

	templatePath = "./tests/json-template.json"
	bin, err = os.ReadFile(templatePath)
	require.Nil(t, err, "failed to load example template")
	jsonTemplate = Template{}
	err = json.Unmarshal(bin, &jsonTemplate)
	require.Nil(t, err, "failed to unmarshal json template")
	yamlBin, err := yaml.Marshal(jsonTemplate)
	require.Nil(t, err, "failed to marshal template to yaml")
	yamlTemplate = Template{}
	err = yaml.Unmarshal(yamlBin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
}
