package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

// ProtocolType is the type of the request protocol specified
type ProtocolType int

// Supported values for the ProtocolType
const (
	DNSProtocol ProtocolType = iota + 1
	FileProtocol
	HTTPProtocol
	HeadlessProtocol
	NetworkProtocol
	WorkflowProtocol
	SSLProtocol
	WebsocketProtocol
	limit
	InvalidProtocol
)

// ExtractorTypes is a table for conversion of extractor type from string.
var protocolMappings = map[ProtocolType]string{
	InvalidProtocol:   "invalid",
	DNSProtocol:       "dns",
	FileProtocol:      "file",
	HTTPProtocol:      "http",
	HeadlessProtocol:  "headless",
	NetworkProtocol:   "network",
	WorkflowProtocol:  "workflow",
	SSLProtocol:       "ssl",
	WebsocketProtocol: "websocket",
}

func GetSupportedProtocolTypes() ProtocolTypes {
	var result []ProtocolType
	for index := ProtocolType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toProtocolType(valueToMap string) (ProtocolType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range protocolMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid protocol type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t ProtocolType) String() string {
	return protocolMappings[t]
}

// TypeHolder is used to hold internal type of the protocol
type TypeHolder struct {
	ProtocolType ProtocolType
}

func (holder TypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of the protocol",
		Description: "Type of the protocol",
	}
	for _, types := range GetSupportedProtocolTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *TypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toProtocolType(marshalledTypes)
	if err != nil {
		return err
	}

	holder.ProtocolType = computedType
	return nil
}

func (holder *TypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.ProtocolType.String())
}

func (holder TypeHolder) MarshalYAML() (interface{}, error) {
	return holder.ProtocolType.String(), nil
}

type ProtocolTypes []ProtocolType

func (protocolTypes *ProtocolTypes) Set(values string) error {
	inputTypes, err := goflags.ToNormalizedStringSlice(values)
	if err != nil {
		return err
	}

	for _, inputType := range inputTypes {
		if err := setProtocolType(protocolTypes, inputType); err != nil {
			return err
		}
	}
	return nil
}

func (protocolTypes *ProtocolTypes) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var stringSliceValue stringslice.StringSlice
	if err := unmarshal(&stringSliceValue); err != nil {
		return err
	}

	stringSLice := stringSliceValue.ToSlice()
	var result = make(ProtocolTypes, 0, len(stringSLice))
	for _, typeString := range stringSLice {
		if err := setProtocolType(&result, typeString); err != nil {
			return err
		}
	}
	*protocolTypes = result
	return nil
}

func (protocolTypes ProtocolTypes) String() string {
	var stringTypes []string
	for _, t := range protocolTypes {
		stringTypes = append(stringTypes, t.String())
	}
	return strings.Join(stringTypes, ", ")
}

func setProtocolType(protocolTypes *ProtocolTypes, value string) error {
	computedType, err := toProtocolType(value)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid extract type", value)
	}
	*protocolTypes = append(*protocolTypes, computedType)
	return nil
}
