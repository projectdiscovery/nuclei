package types

import (
	"fmt"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// ProtocolType is the type of the request protocol specified
type ProtocolType int

// Supported values for the ProtocolType
// name:ProtocolType
const (
	// name:dns
	DNSProtocol ProtocolType = iota + 1
	// name:file
	FileProtocol
	// name:http
	HTTPProtocol
	// name:offline-http
	OfflineHTTPProtocol
	// name:headless
	HeadlessProtocol
	// name:network
	NetworkProtocol
	// name:workflow
	WorkflowProtocol
	// name:ssl
	SSLProtocol
	// name:websocket
	WebsocketProtocol
	// name:whois
	WHOISProtocol
	// name:code
	CodeProtocol
	// name: js
	JavascriptProtocol
	limit
	InvalidProtocol
)

// ExtractorTypes is a table for conversion of extractor type from string.
var protocolMappings = map[ProtocolType]string{
	InvalidProtocol:    "invalid",
	DNSProtocol:        "dns",
	FileProtocol:       "file",
	HTTPProtocol:       "http",
	HeadlessProtocol:   "headless",
	NetworkProtocol:    "tcp",
	WorkflowProtocol:   "workflow",
	SSLProtocol:        "ssl",
	WebsocketProtocol:  "websocket",
	WHOISProtocol:      "whois",
	CodeProtocol:       "code",
	JavascriptProtocol: "javascript",
}

func GetSupportedProtocolTypes() ProtocolTypes {
	var result []ProtocolType
	for index := ProtocolType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

// SupportedProtocolsStrings returns a slice of strings of supported protocols
func SupportedProtocolsStrings() []string {
	var result []string
	for _, protocol := range GetSupportedProtocolTypes() {
		if protocol.String() == "" {
			continue
		}
		result = append(result, protocol.String())
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
	ProtocolType ProtocolType `mapping:"true"`
}

func (holder TypeHolder) JSONSchema() *jsonschema.Schema {
	gotType := &jsonschema.Schema{
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
	inputTypes, err := goflags.ToStringSlice(values, goflags.FileNormalizedStringSliceOptions)
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

func (protocolTypes ProtocolTypes) MarshalJSON() ([]byte, error) {
	var stringProtocols = make([]string, 0, len(protocolTypes))
	for _, protocol := range protocolTypes {
		stringProtocols = append(stringProtocols, protocol.String())
	}
	return json.Marshal(stringProtocols)
}

func (protocolTypes ProtocolTypes) String() string {
	var stringTypes []string
	for _, t := range protocolTypes {
		protocolMapping := t.String()
		if protocolMapping != "" {
			stringTypes = append(stringTypes, protocolMapping)
		}

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
