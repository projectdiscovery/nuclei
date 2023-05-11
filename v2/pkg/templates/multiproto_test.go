package templates

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TODO: add more tests
// unmarshall json and yaml templates for multi protocol requests

func TestUnmarshalMulti(t *testing.T) {
	tpath := "/Users/tarun/test-templates/multi.yaml"
	bin, err := os.ReadFile(tpath)
	require.Nil(t, err, "failed to load example template")
	var yamlTemplate Template
	err = yaml.Unmarshal(bin, &yamlTemplate)
	require.Nil(t, err, "failed to unmarshal yaml template")
	t.Log(yamlTemplate.MultiProtoRequest.Queue)
}
