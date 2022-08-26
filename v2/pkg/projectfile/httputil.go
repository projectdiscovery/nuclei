package projectfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"io"
	"net/http"
)

func hash(v interface{}) (string, error) {
	data, err := marshal(v)
	if err != nil {
		return "", err
	}

	sh := sha256.New()

	if _, err = io.WriteString(sh, string(data)); err != nil {
		return "", err
	}
	return hex.EncodeToString(sh.Sum(nil)), nil
}

func marshal(data interface{}) ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	if err := enc.Encode(data); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func unmarshal(data []byte, obj interface{}) error {
	dec := gob.NewDecoder(bytes.NewBuffer(data))
	if err := dec.Decode(obj); err != nil {
		return err
	}

	return nil
}

type HTTPRecord struct {
	Request  []byte
	Response *InternalResponse
}

type InternalRequest struct {
	Target    string
	HTTPMajor int
	HTTPMinor int
	Method    string
	Headers   map[string][]string
	Body      []byte
}

type InternalResponse struct {
	HTTPMajor    int
	HTTPMinor    int
	StatusCode   int
	StatusReason string
	Headers      map[string][]string
	Body         []byte
}

// Unused
// func newInternalRequest() *InternalRequest {
// 	return &InternalRequest{
// 		Headers: make(map[string][]string),
// 	}
// }

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
	var contentLength int64
	if intResp.Body != nil {
		contentLength = int64(len(intResp.Body))
	}
	return &http.Response{
		ProtoMinor:    intResp.HTTPMinor,
		ProtoMajor:    intResp.HTTPMajor,
		Status:        intResp.StatusReason,
		StatusCode:    intResp.StatusCode,
		Header:        intResp.Headers,
		ContentLength: contentLength,
		Body:          io.NopCloser(bytes.NewReader(intResp.Body)),
	}
}
