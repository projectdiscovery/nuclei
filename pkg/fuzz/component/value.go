package component

import (
	"strconv"

	"github.com/leslie-qiwa/flat"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
)

// Value is a value component containing a single
// parameter for the component
//
// It is a type of container that is used to represent
// all the data values that are used in a request.
type Value struct {
	data       string
	parsed     map[string]interface{}
	dataFormat string
}

// NewValue returns a new value component
func NewValue(data string) *Value {
	if data == "" {
		return &Value{}
	}
	v := &Value{data: data}

	// Do any dataformat decoding on the data if needed
	decodedDataformat, err := dataformat.Decode(data)
	if err == nil && decodedDataformat != nil {
		v.SetParsed(decodedDataformat.Data, decodedDataformat.DataFormat)
	}
	return v
}

// String returns the string representation of the value
func (v *Value) String() string {
	return v.data
}

// Parsed returns the parsed value
func (v *Value) Parsed() map[string]interface{} {
	return v.parsed
}

// SetParsed sets the parsed value map
func (v *Value) SetParsed(parsed map[string]interface{}, dataFormat string) {
	flattened, err := flat.Flatten(parsed, flatOpts)
	if err == nil {
		v.parsed = flattened
	} else {
		v.parsed = parsed
	}
	v.dataFormat = dataFormat
}

// SetParsedValue sets the parsed value for a key
// in the parsed map
func (v *Value) SetParsedValue(key string, value string) bool {
	origValue, ok := v.parsed[key]
	if !ok {
		v.parsed[key] = value
		return true
	}
	// If the value is a list, append to it
	// otherwise replace it
	switch v := origValue.(type) {
	case []interface{}:
		origValue = append(v, value)
	case string:
		origValue = value
	case int, int32, int64, float32, float64:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return false
		}
		origValue = parsed
	case bool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false
		}
		origValue = parsed
	case nil:
		origValue = value
	default:
		gologger.Error().Msgf("unknown type %T for value %s", v, v)
	}
	v.parsed[key] = origValue
	return true
}

// Delete removes a key from the parsed value
func (v *Value) Delete(key string) bool {
	if _, ok := v.parsed[key]; !ok {
		return false
	}
	delete(v.parsed, key)
	return true
}

// Encode encodes the value into a string
// using the dataformat and encoding
func (v *Value) Encode() (string, error) {
	toEncodeStr := v.data

	nested, err := flat.Unflatten(v.parsed, flatOpts)
	if err != nil {
		return "", err
	}
	if v.dataFormat != "" {
		dataformatStr, err := dataformat.Encode(nested, v.dataFormat)
		if err != nil {
			return "", err
		}
		toEncodeStr = dataformatStr
	}
	return toEncodeStr, nil
}
