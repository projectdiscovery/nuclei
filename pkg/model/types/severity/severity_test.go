package severity

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/stretchr/testify/require"
)

func TestYamlUnmarshal(t *testing.T) {
	testUnmarshal(t, yaml.Unmarshal, func(value string) string { return value })
}

func TestYamlMarshal(t *testing.T) {
	severity := Holder{Severity: High}

	marshalled, err := severity.MarshalYAML()
	require.Nil(t, err, "could not marshal yaml")
	require.Equal(t, "high", marshalled, "could not marshal severity correctly")
}

func TestYamlUnmarshalFail(t *testing.T) {
	testUnmarshalFail(t, yaml.Unmarshal, createYAML)
}

func TestGetSupportedSeverities(t *testing.T) {
	severities := GetSupportedSeverities()
	require.Equal(t, severities, Severities{Info, Low, Medium, High, Critical, Unknown})
}

func testUnmarshal(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	t.Helper()
	payloads := [...]string{
		payloadCreator("Info"),
		payloadCreator("info"),
		payloadCreator("inFo "),
		payloadCreator("infO "),
		payloadCreator(" INFO "),
	}

	for _, payload := range payloads { // nolint:scopelint // false-positive
		t.Run(payload, func(t *testing.T) {
			result := unmarshal(payload, unmarshaller)
			require.Equal(t, result.Severity, Info)
			require.Equal(t, result.Severity.String(), "info")
		})
	}
}

func testUnmarshalFail(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	t.Helper()
	require.Panics(t, func() { unmarshal(payloadCreator("invalid"), unmarshaller) })
}

func unmarshal(value string, unmarshaller func(data []byte, v interface{}) error) Holder {
	severityStruct := Holder{}
	var err = unmarshaller([]byte(value), &severityStruct)
	if err != nil {
		panic(err)
	}
	return severityStruct
}

func createYAML(value string) string {
	return "severity: " + value + "\n"
}

func TestMarshalJSON(t *testing.T) {
	unmarshalled := Severities{Low, Medium}
	data, err := unmarshalled.MarshalJSON()
	if err != nil {
		panic(err)
	}
	require.Equal(t, "[\"low\",\"medium\"]", string(data), "could not marshal json")
}

func TestSeveritiesMarshalYaml(t *testing.T) {
	unmarshalled := Severities{Low, Medium}
	marshalled, err := yaml.Marshal(unmarshalled)
	if err != nil {
		panic(err)
	}
	require.Equal(t, "- low\n- medium\n", string(marshalled), "could not marshal yaml")
}
