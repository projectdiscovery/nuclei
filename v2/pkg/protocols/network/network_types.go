package network

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// NetworkType is the type of the method specified
type NetworkType int

const (
	hexType NetworkType = iota + 1
	textType
	//limit
	limit
)

// NetworkMapping is a table for conversion of method from string.
var NetworkMapping = map[NetworkType]string{
	hexType:  "hex",
	textType: "text",
}

// GetSupportedNetworkTypes returns list of supported types
func GetSupportedNetworkTypes() []NetworkType {
	var result []NetworkType
	for index := NetworkType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toNetworkTypes(valueToMap string) (NetworkType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range NetworkMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid network type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t NetworkType) String() string {
	return NetworkMapping[t]
}

// NetworkTypeHolder is used to hold internal type of the Network type
type NetworkTypeHolder struct {
	NetworkType NetworkType
}

func (holder NetworkTypeHolder) GetType() NetworkType {
	return holder.NetworkType
}

func (holder NetworkTypeHolder) String() string {
	return holder.NetworkType.String()
}

func (holder NetworkTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type is the type of input data",
		Description: "description=Type of input specified in data field,enum=hex,enum=text",
	}
	for _, types := range GetSupportedNetworkTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *NetworkTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toNetworkTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.NetworkType = computedType
	return nil
}

func (holder *NetworkTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.NetworkType.String())
}

func (holder NetworkTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.NetworkType.String(), nil
}
