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

func testUnmarshal(t *testing.T, unmarshaler func(data []byte, v interface{}) error, payloadCreator func(value string) string) {
	payloads := [...]string{
		payloadCreator("Info"),
		payloadCreator("info"),
		payloadCreator("inFo "),
		payloadCreator("infO "),
		payloadCreator(" INFO "),
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			result := unmarshal(payload, unmarshaler)
			assert.Equal(t, result.Key, Info)
			assert.Equal(t, result.Key.String(), "info")
		})
	}
}

func testMarshal(t *testing.T, marshaller func(v interface{}) ([]byte, error), payloadCreator func(value string) string) {
	for _, severity := range GetSupportedSeverities() {
		result, _ := marshaller(&SeverityStruct{Key: severity})
		assert.Equal(t, string(result), payloadCreator(severity.String()))
	}
}

func testUnmarshalFail(t *testing.T, unmarshaler func(data []byte, v interface{}) error, payloadCreator func(value string) string) bool {
	return assert.Panics(t, func() { unmarshal(payloadCreator("invalid"), unmarshaler) })
}

func testMarshallerFails(t *testing.T, marshaller func(v interface{}) ([]byte, error)) {
	assert.Panics(t, func() { marshaller(&SeverityStruct{Key: 13}) })
}

func unmarshal(value string, unmarshaller func(data []byte, v interface{}) error) SeverityStruct {
	severityStruct := SeverityStruct{}
	var err = unmarshaller([]byte(value), &severityStruct)
	if err != nil {
		panic(err)
	}
	return severityStruct
}

func createJson(severityString string) string {
	return fmt.Sprintf(`{"Key":"%s"}`, severityString)
}

func createYaml(value string) string {
	return "key: " + value + "\n"
}
