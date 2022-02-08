package network

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// NetworkInputType is the type of the network input specified
type NetworkInputType int

// name:NetworkInputType
const (
	// name:hex
	hexType NetworkInputType = iota + 1
	// name:text
	textType
	limit
)

// NetworkInputMapping is a table for conversion of method from string.
var NetworkInputMapping = map[NetworkInputType]string{
	hexType:  "hex",
	textType: "text",
}

// GetSupportedNetworkInputTypes returns list of supported types
func GetSupportedNetworkInputTypes() []NetworkInputType {
	var result []NetworkInputType
	for index := NetworkInputType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toNetworkInputTypes(valueToMap string) (NetworkInputType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range NetworkInputMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid network type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t NetworkInputType) String() string {
	return NetworkInputMapping[t]
}

// NetworkInputTypeHolder is used to hold internal type of the Network type
type NetworkInputTypeHolder struct {
	NetworkInputType NetworkInputType `mapping:"true"`
}

func (holder NetworkInputTypeHolder) GetType() NetworkInputType {
	return holder.NetworkInputType
}

func (holder NetworkInputTypeHolder) String() string {
	return holder.NetworkInputType.String()
}

func (holder NetworkInputTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type is the type of input data",
		Description: "description=Type of input specified in data field",
	}
	for _, types := range GetSupportedNetworkInputTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *NetworkInputTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toNetworkInputTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.NetworkInputType = computedType
	return nil
}

func (holder *NetworkInputTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.NetworkInputType.String())
}

func (holder NetworkInputTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.NetworkInputType.String(), nil
}
