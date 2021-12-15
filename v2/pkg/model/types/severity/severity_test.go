package severity

import (
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
)

func TestYamlUnmarshal(t *testing.T) {
	testUnmarshal(t, yaml.Unmarshal, func(value string) string { return value })
}

func TestYamlMarshal(t *testing.T) {
	severity := Holder{Severity: High}

	marshalled, err := severity.MarshalYAML()
	assert.Nil(t, err, "could not marshal yaml")
	assert.Equal(t, "high", marshalled, "could not marshal severity correctly")
}

func TestYamlUnmarshalFail(t *testing.T) {
	testUnmarshalFail(t, yaml.Unmarshal, createYAML)
}

func TestGetSupportedSeverities(t *testing.T) {
	severities := GetSupportedSeverities()
	assert.Equal(t, severities, Severities{Info, Low, Medium, High, Critical})
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
			assert.Equal(t, result.Severity, Info)
			assert.Equal(t, result.Severity.String(), "info")
		})
	}
}

func testUnmarshalFail(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	t.Helper()
	assert.Panics(t, func() { unmarshal(payloadCreator("invalid"), unmarshaller) })
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
