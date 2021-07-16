package severity

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"testing"
)

func TestJsonUnmarshal(t *testing.T) {
	testUnmarshal(t, json.Unmarshal, createJson)
}

func TestYamlUnmarshal(t *testing.T) {
	testUnmarshal(t, yaml.Unmarshal, createYaml)
}

func TestJsonUnmarshalFail(t *testing.T) {
	testUnmarshalFail(t, json.Unmarshal, createJson)
}

func TestYamlUnmarshalFail(t *testing.T) {
	testUnmarshalFail(t, yaml.Unmarshal, createYaml)
}

func TestJsonMarshalFails(t *testing.T) {
	testMarshallerFails(t, json.Marshal)
}

func TestYamlMarshalFails(t *testing.T) {
	testMarshallerFails(t, yaml.Marshal)
}

func TestJsonMarshalSucceed(t *testing.T) {
	testMarshal(t, json.Marshal, createJson)
}

func TestYamlMarshal(t *testing.T) {
	testMarshal(t, yaml.Marshal, createYaml)
}

func testUnmarshal(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	payloads := [...]string{
		payloadCreator("Info"),
		payloadCreator("info"),
		payloadCreator("inFo "),
		payloadCreator("infO "),
		payloadCreator(" INFO "),
	}

	for _, payload := range payloads {
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

func testUnmarshalFail(t *testing.T, unmarshaller func(data []byte, v interface{}) error, payloadCreator func(value string) string) bool {
	return assert.Panics(t, func() { unmarshal(payloadCreator("invalid"), unmarshaller) })
}

func testMarshallerFails(t *testing.T, marshaller func(v interface{}) ([]byte, error)) {
	assert.Panics(t, func() { marshaller(&SeverityHolder{Severity: 13}) })
}

func unmarshal(value string, unmarshaller func(data []byte, v interface{}) error) SeverityHolder {
	severityStruct := SeverityHolder{}
	var err = unmarshaller([]byte(value), &severityStruct)
	if err != nil {
		panic(err)
	}
	return severityStruct
}

func createJson(severityString string) string {
	return fmt.Sprintf(`{"Severity":"%s"}`, severityString)
}

func createYaml(value string) string {
	return "severity: " + value + "\n"
}
