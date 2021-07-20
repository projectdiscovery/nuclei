package severity

import (
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/assert"
)

func TestYamlUnmarshal(t *testing.T) {
	testUnmarshal(t, yaml.Unmarshal, func(value string) string { return value })
}

func TestYamlUnmarshalFail(t *testing.T) {
	testUnmarshalFail(t, yaml.Unmarshal, createYAML)
}

func TestYamlMarshalFails(t *testing.T) {
	testMarshallerFails(t, yaml.Marshal)
}

func TestYamlMarshal(t *testing.T) {
	testMarshal(t, yaml.Marshal, createYAML)
}

func testUnmarshal(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
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

func testMarshal(t *testing.T, marshaller func(v interface{}) ([]byte, error), payloadCreator func(value string) string) {
	for _, severity := range GetSupportedSeverities() {
		result, _ := marshaller(&SeverityHolder{Severity: severity})
		assert.Equal(t, string(result), payloadCreator(severity.String()))
	}
}

func testUnmarshalFail(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	assert.Panics(t, func() { unmarshal(payloadCreator("invalid"), unmarshaller) })
}

func testMarshallerFails(t *testing.T, marshaller func(v interface{}) ([]byte, error)) {
	assert.Panics(t, func() { _, _ = marshaller(&SeverityHolder{Severity: 13}) })
}

func unmarshal(value string, unmarshaller func(data []byte, v interface{}) error) SeverityHolder {
	severityStruct := SeverityHolder{}
	var err = unmarshaller([]byte(value), &severityStruct)
	if err != nil {
		panic(err)
	}
	return severityStruct
}

func createYAML(value string) string {
	return "severity: " + value + "\n"
}
