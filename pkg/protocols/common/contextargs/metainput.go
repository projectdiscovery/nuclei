package contextargs

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	urlutil "github.com/projectdiscovery/utils/url"
)

// MetaInput represents a target with metadata (TODO: replace with https://github.com/projectdiscovery/metainput)
type MetaInput struct {
	// Input represent the target
	Input string `json:"input,omitempty"`
	// CustomIP to use for connection
	CustomIP string `json:"customIP,omitempty"`
	// hash of the input
	hash string `json:"-"`

	// ReqResp is the raw request for the input
	ReqResp *types.RequestResponse `json:"raw-request,omitempty"`
}

func (metaInput *MetaInput) marshalToBuffer() (bytes.Buffer, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(metaInput)
	return b, err
}

// Target returns the target of the metainput
func (metaInput *MetaInput) Target() string {
	if metaInput.ReqResp != nil && metaInput.ReqResp.URL.URL != nil {
		return metaInput.ReqResp.URL.String()
	}
	return metaInput.Input
}

// URL returns request url
func (metaInput *MetaInput) URL() (*urlutil.URL, error) {
	instance, err := urlutil.ParseAbsoluteURL(metaInput.Target(), false)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// ID returns a unique id/hash for metainput
func (metaInput *MetaInput) ID() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s-%s", metaInput.Input, metaInput.CustomIP)
	}
	if metaInput.ReqResp != nil {
		return metaInput.ReqResp.ID()
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
	if metaInput.ReqResp != nil {
		input.ReqResp = metaInput.ReqResp.Clone()
	}
	return input
}

func (metaInput *MetaInput) PrettyPrint() string {
	if metaInput.CustomIP != "" {
		return fmt.Sprintf("%s [%s]", metaInput.Input, metaInput.CustomIP)
	}
	if metaInput.ReqResp != nil {
		return fmt.Sprintf("%s [%s]", metaInput.ReqResp.URL.String(), metaInput.ReqResp.Request.Method)
	}
	return metaInput.Input
}

// GetScanHash returns a unique hash that represents a scan by hashing (metainput + templateId)
func (metaInput *MetaInput) GetScanHash(templateId string) string {
	// there may be some cases where metainput is changed ex: while executing self-contained template etc
	// but that totally changes the scanID/hash so to avoid that we compute hash only once
	// and reuse it for all subsequent calls
	if metaInput.hash == "" {
		var rawRequest string
		if metaInput.ReqResp != nil {
			rawRequest = metaInput.ReqResp.ID()
		}
		metaInput.hash = getMd5Hash(templateId + ":" + metaInput.Input + ":" + metaInput.CustomIP + rawRequest)
	}
	return metaInput.hash
}

func getMd5Hash(data string) string {
	bin := md5.Sum([]byte(data))
	return string(bin[:])
}
