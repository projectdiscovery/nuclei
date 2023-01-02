package contextargs

import (
	"bytes"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// MetaInput represents a target with metadata (TODO: replace with https://github.com/projectdiscovery/metainput)
type MetaInput struct {
	// Input represent the target
	Input string `json:"input,omitempty"`
	// CustomIP to use for connection
	CustomIP string `json:"customIP,omitempty"`
}

func (metaInput *MetaInput) marshalToBuffer() (bytes.Buffer, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(metaInput)
	return b, err
}

// ID returns a unique id/hash for metainput
func (metaInput *MetaInput) ID() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s-%s", metaInput.Input, metaInput.CustomIP)
	}
	return metaInput.Input
}

func (metaInput *MetaInput) MarshalString() (string, error) {
	b, err := metaInput.marshalToBuffer()
	return b.String(), err
}

func (metaInput *MetaInput) MustMarshalString() string {
	marshaled, _ := metaInput.MarshalString()
	return marshaled
}

func (metaInput *MetaInput) MarshalBytes() ([]byte, error) {
	b, err := metaInput.marshalToBuffer()
	return b.Bytes(), err
}

func (metaInput *MetaInput) MustMarshalBytes() []byte {
	marshaled, _ := metaInput.MarshalBytes()
	return marshaled
}

func (metaInput *MetaInput) Unmarshal(data string) error {
	return jsoniter.NewDecoder(strings.NewReader(data)).Decode(metaInput)
}

func (metaInput *MetaInput) Clone() *MetaInput {
	return &MetaInput{
		Input:    metaInput.Input,
		CustomIP: metaInput.CustomIP,
	}
}

func (metaInput *MetaInput) PrettyPrint() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s [%s]", metaInput.Input, metaInput.CustomIP)
	}
	return metaInput.Input
}
