package dataformat

import (
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// JSON is a JSON encoder
//
// For now JSON only supports objects as the root data type
// and not arrays
//
// TODO: Support arrays + other JSON oddities by
// adding more attirbutes to the map[string]interface{}
type JSON struct{}

var (
	_ DataFormat = &JSON{}
)

// NewJSON returns a new JSON encoder
func NewJSON() *JSON {
	return &JSON{}
}

// IsType returns true if the data is JSON encoded
func (j *JSON) IsType(data string) bool {
	return strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}")
}

// Encode encodes the data into JSON format
func (j *JSON) Encode(data KV) (string, error) {
	encoded, err := jsoniter.Marshal(data.Map)
	return string(encoded), err
}

// Decode decodes the data from JSON format
func (j *JSON) Decode(data string) (KV, error) {
	var decoded map[string]interface{}
	err := jsoniter.Unmarshal([]byte(data), &decoded)
	return KVMap(decoded), err
}

// Name returns the name of the encoder
func (j *JSON) Name() string {
	return JSONDataFormat
}
