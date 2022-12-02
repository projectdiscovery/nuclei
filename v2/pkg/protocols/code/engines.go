package code

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// EngineType is the type of the method specified
type EngineType int

// name:EngineType
const (
	// name:python
	Python EngineType = iota + 1
	// name:powershell
	Powershell
	// name:echo
	Echo
	limit
)

func (t EngineType) Executable() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("%s.exe", t.String())
	}
	return t.String()
}

func (t EngineType) String() string {
	return EngineTypeMapping[t]
}

// DNSRequestTypeMapping is a table for conversion of method from string.
var EngineTypeMapping = map[EngineType]string{
	Echo:       "echo",
	Python:     "python",
	Powershell: "powershell",
}

// GetSupportedEngines returns list of supported engines
func GetSupportedEngines() []EngineType {
	var result []EngineType
	for index := EngineType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toEngineType(valueToMap string) (EngineType, error) {
	normalizedValue := strings.TrimSpace(valueToMap)
	for key, currentValue := range EngineTypeMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid Engine type: " + valueToMap)
}

// DNSRequestTypeHolder is used to hold internal type of the Engine type
type EngineTypeHolder struct {
	EngineType EngineType `mapping:"true"`
}

func (holder EngineTypeHolder) String() string {
	return holder.EngineType.String()
}

func (holder EngineTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of engine",
		Description: "Type is the type of engine to make",
	}
	for _, types := range GetSupportedEngines() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *EngineTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toEngineType(marshalledTypes)
	if err != nil {
		return err
	}

	holder.EngineType = computedType
	return nil
}

func (holder *EngineTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.EngineType.String())
}

func (holder EngineTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.EngineType.String(), nil
}
