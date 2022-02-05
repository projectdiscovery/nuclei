package dns

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// DNSRequestType is the type of the method specified
type DNSRequestType int

// name:DNSRequestType
const (
	// name:A
	A DNSRequestType = iota + 1
	// name:NS
	NS
	// name:DS
	DS
	// name:CNAME
	CNAME
	// name:SOA
	SOA
	// name:PTR
	PTR
	// name:MX
	MX
	// name:TXT
	TXT
	// name:AAAA
	AAAA
	// name:CAA
	CAA
	limit
)

// DNSRequestTypeMapping is a table for conversion of method from string.
var DNSRequestTypeMapping = map[DNSRequestType]string{
	A:     "A",
	NS:    "NS",
	DS:    "DS",
	CNAME: "CNAME",
	SOA:   "SOA",
	PTR:   "PTR",
	MX:    "MX",
	TXT:   "TXT",
	AAAA:  "AAAA",
	CAA:   "CAA",
}

// GetSupportedDNSRequestTypes returns list of supported types
func GetSupportedDNSRequestTypes() []DNSRequestType {
	var result []DNSRequestType
	for index := DNSRequestType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toDNSRequestTypes(valueToMap string) (DNSRequestType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range DNSRequestTypeMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid DNS request type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToUpper(value))
}

func (t DNSRequestType) String() string {
	return DNSRequestTypeMapping[t]
}

// DNSRequestTypeHolder is used to hold internal type of the DNS type
type DNSRequestTypeHolder struct {
	DNSRequestType DNSRequestType `mapping:"true"`
}

func (holder DNSRequestTypeHolder) String() string {
	return holder.DNSRequestType.String()
}

func (holder DNSRequestTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of DNS request to make",
		Description: "Type is the type of DNS request to make",
	}
	for _, types := range GetSupportedDNSRequestTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *DNSRequestTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toDNSRequestTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.DNSRequestType = computedType
	return nil
}

func (holder *DNSRequestTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.DNSRequestType.String())
}

func (holder DNSRequestTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.DNSRequestType.String(), nil
}
