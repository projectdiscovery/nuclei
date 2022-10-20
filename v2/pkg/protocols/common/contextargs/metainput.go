package contextargs

import (
	"bytes"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// MetaInput represents a target with metadata (TODO: replace with https://github.com/projectdiscovery/metainput)
type MetaInput struct {
	// Input represent the target
	Input string
	// CustomIP to use for connection
	CustomIP string
	// jsonMarsheled contains the marshaled version of metainput
	// it's ok to marshal once since the struct it's supposed to be static
	jsonMarsheled string
}

func (metaInput *MetaInput) Marshal() (string, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(metaInput)
	return b.String(), err
}

func (metaInput *MetaInput) Unmarshal(data string) error {
	return jsoniter.NewDecoder(strings.NewReader(data)).Decode(metaInput)
}

func (metaInput *MetaInput) String() string {
	if metaInput.jsonMarsheled != "" {
		return metaInput.jsonMarsheled
	}
	metaInput.jsonMarsheled, _ = metaInput.Marshal()
	return metaInput.jsonMarsheled
}
