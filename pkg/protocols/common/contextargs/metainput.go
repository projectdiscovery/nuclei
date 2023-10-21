package contextargs

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
)

// MetaInput represents a target with metadata (TODO: replace with https://github.com/projectdiscovery/metainput)
type MetaInput struct {
	// Input represent the target
	Input string `json:"input,omitempty"`
	// CustomIP to use for connection
	CustomIP string `json:"customIP,omitempty"`
	// hash of the input
	hash string `json:"-"`

	// RawRequest is the raw request for the input
	RawRequest *formats.RawRequest `json:"raw-request,omitempty"`
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
	if metaInput.RawRequest != nil {
		return metaInput.RawRequest.ID()
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
	input := &MetaInput{
		Input:    metaInput.Input,
		CustomIP: metaInput.CustomIP,
	}
	if metaInput.RawRequest != nil {
		input.RawRequest = &formats.RawRequest{
			URL:     metaInput.RawRequest.URL,
			Headers: cloneMap(metaInput.RawRequest.Headers),
			Body:    metaInput.RawRequest.Body,
			Method:  metaInput.RawRequest.Method,
			Raw:     metaInput.RawRequest.Raw,
		}
	}
	return input
}

func cloneMap(m map[string][]string) map[string][]string {
	clone := make(map[string][]string)
	for k, v := range m {
		clone[k] = v
	}
	return clone
}

func (metaInput *MetaInput) PrettyPrint() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s [%s]", metaInput.Input, metaInput.CustomIP)
	}
	if metaInput.RawRequest != nil {
		return fmt.Sprintf("%s [%s]", metaInput.RawRequest.URL, metaInput.RawRequest.Method)
	}
	return metaInput.Input
}

// GetScanHash returns a unique hash that represents a scan by hashing (metainput + templateId)
func (metaInput *MetaInput) GetScanHash(templateId string) string {
	// there may be some cases where metainput is changed ex: while executing self-contained template etc
	// but that totally changes the scanID/hash so to avoid that we compute hash only once
	// and reuse it for all subsequent calls
	if metaInput.hash == "" {
		var builder bytes.Buffer
		builder.WriteString(templateId)
		builder.WriteString(":")
		builder.WriteString(metaInput.Input)
		builder.WriteString(":")
		builder.WriteString(metaInput.CustomIP)
		if metaInput.RawRequest != nil {
			builder.WriteString(":")
			builder.WriteString(metaInput.RawRequest.ID())
		}
		metaInput.hash = getMd5Hash(builder.Bytes())
	}
	return metaInput.hash
}

func getMd5Hash(data []byte) string {
	bin := md5.Sum(data)
	return string(bin[:])
}
