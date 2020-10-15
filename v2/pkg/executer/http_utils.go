package executer

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"unsafe"
)

type jsonOutput struct {
	Template         string                 `json:"template"`
	Type             string                 `json:"type"`
	Matched          string                 `json:"matched"`
	MatcherName      string                 `json:"matcher_name,omitempty"`
	ExtractedResults []string               `json:"extracted_results,omitempty"`
	Name             string                 `json:"name"`
	Severity         string                 `json:"severity"`
	Author           string                 `json:"author"`
	Description      string                 `json:"description"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	Meta             map[string]interface{} `json:"meta,omitempty"`
}

// unsafeToString converts byte slice to string with zero allocations
func unsafeToString(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

// headersToString converts http headers to string
func headersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)

			if i != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}

		builder.WriteRune('\n')
	}

	return builder.String()
}

func hash(v interface{}) (string, error) {
	data, err := marshal(v)
	if err != nil {
		return "", err
	}

	sh := sha256.New()

	io.WriteString(sh, string(data))
	return hex.EncodeToString(sh.Sum(nil)), nil
}

func marshal(data interface{}) ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func unmarshal(data []byte, obj interface{}) error {
	var b bytes.Buffer
	dec := gob.NewDecoder(&b)
	err := dec.Decode(obj)
	if err != nil {
		return err
	}

	return nil
}

type InternalResponse struct {
	HTTPMajor    int
	HTTPMinor    int
	StatusCode   int
	StatusReason string
	Headers      map[string][]string
	Body         []byte
}

func newInternalResponse() *InternalResponse {
	return &InternalResponse{
		Headers: make(map[string][]string),
	}
}

func toInternalResponse(resp *http.Response, body []byte) *InternalResponse {
	intResp := newInternalResponse()

	intResp.HTTPMajor = resp.ProtoMajor
	intResp.HTTPMinor = resp.ProtoMinor
	intResp.StatusCode = resp.StatusCode
	intResp.StatusReason = resp.Status
	for k, v := range resp.Header {
		intResp.Headers[k] = v
	}
	intResp.Body = body
	return intResp
}

func fromInternalResponse(intResp *InternalResponse) *http.Response {
	return &http.Response{
		ProtoMinor:    intResp.HTTPMinor,
		ProtoMajor:    intResp.HTTPMajor,
		Status:        intResp.StatusReason,
		StatusCode:    intResp.StatusCode,
		Header:        intResp.Headers,
		ContentLength: int64(len(intResp.Body)),
		Body:          ioutil.NopCloser(bytes.NewReader(intResp.Body)),
	}
}
