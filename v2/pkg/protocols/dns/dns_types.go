package dns

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// DnsType is the type of the method specified
type DnsType int

const (
	A DnsType = iota + 1
	NS
	DS
	CNAME
	SOA
	PTR
	MX
	TXT
	AAAA
	//limit
	limit
)

// DnsTypeMapping is a table for conversion of method from string.
var DnsTypeMapping = map[DnsType]string{
	A:     "A",
	NS:    "NS",
	DS:    "DS",
	CNAME: "CNAME",
	SOA:   "SOA",
	PTR:   "PTR",
	MX:    "MX",
	TXT:   "TXT",
	AAAA:  "AAAA",
}

// GetSupportedDnsTypes returns list of supported types
func GetSupportedDnsTypes() []DnsType {
	var result []DnsType
	for index := DnsType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toDnsTypes(valueToMap string) (DnsType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range DnsTypeMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid dns type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToUpper(value))
}

func (t DnsType) String() string {
	return DnsTypeMapping[t]
}

// DnsTypeHolder is used to hold internal type of the Dns type
type DnsTypeHolder struct {
	DnsType DnsType
}

func (holder DnsTypeHolder) String() string {
	return holder.DnsType.String()
}

func (holder DnsTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of dns request to make",
		Description: "Type is the type of DNS request to make,enum=A,enum=NS,enum=DS,enum=CNAME,enum=SOA,enum=PTR,enum=MX,enum=TXT,enum=AAAA",
	}
	for _, types := range GetSupportedDnsTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *DnsTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toDnsTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.DnsType = computedType
	return nil
}

func (holder *DnsTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.DnsType.String())
}

func (holder DnsTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.DnsType.String(), nil
}
