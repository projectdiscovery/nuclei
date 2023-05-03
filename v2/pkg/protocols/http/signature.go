package http

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/signer"
)

// SignatureType is the type of signature
type SignatureType int

// Supported values for the SignatureType
const (
	AWSSignature SignatureType = iota + 1
	signatureLimit
)

// signatureTypeMappings is a table for conversion of signature type from string.
var signatureTypeMappings = map[SignatureType]string{
	AWSSignature: "AWS",
}

func GetSupportedSignaturesTypes() []SignatureType {
	var result []SignatureType
	for index := SignatureType(1); index < signatureLimit; index++ {
		result = append(result, index)
	}
	return result
}

func toSignatureType(valueToMap string) (SignatureType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range signatureTypeMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("invalid signature type: " + valueToMap)
}

func (t SignatureType) String() string {
	return signatureTypeMappings[t]
}

// SignatureTypeHolder is used to hold internal type of the signature
type SignatureTypeHolder struct {
	Value SignatureType
}

func (holder SignatureTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the signature",
		Description: "Type of the signature",
	}
	for _, types := range GetSupportedSignaturesTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *SignatureTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toSignatureType(marshalledTypes)
	if err != nil {
		return err
	}

	holder.Value = computedType
	return nil
}

func (holder *SignatureTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := toSignatureType(s)
	if err != nil {
		return err
	}

	holder.Value = computedType
	return nil
}

func (holder SignatureTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.Value.String())
}

func (holder SignatureTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.Value.String(), nil
}

var ErrNoIgnoreList = errors.New("unknown signature types")

// GetVariablesNamesSkipList depending on the signature type
func GetVariablesNamesSkipList(signature SignatureType) map[string]interface{} {
	switch signature {
	case AWSSignature:
		return signer.AwsSkipList
	default:
		return nil
	}
}

// GetDefaultSignerVars returns the default signer variables
func GetDefaultSignerVars(signatureType SignatureType) map[string]interface{} {
	if signatureType == AWSSignature {
		return signer.AwsDefaultVars
	}
	return map[string]interface{}{}
}
