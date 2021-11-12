package dns

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/alecthomas/jsonschema"
)

// DNSType is the type of the method specified
type DNSType int

const (
	A DNSType = iota + 1
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

// DNSTypeMapping is a table for conversion of method from string.
var DNSTypeMapping = map[DNSType]string{
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

// GetSupportedDNSTypes returns list of supported types
func GetSupportedDNSTypes() []DNSType {
	var result []DNSType
	for index := DNSType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toDNSTypes(valueToMap string) (DNSType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range DNSTypeMapping {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid DNS type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToUpper(value))
}

func (t DNSType) String() string {
	return DNSTypeMapping[t]
}

// DNSTypeHolder is used to hold internal type of the DNS type
type DNSTypeHolder struct {
	DNSType DNSType
}

func (holder DNSTypeHolder) String() string {
	return holder.DNSType.String()
}

func (holder DNSTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "type of DNS request to make",
		Description: "Type is the type of DNS request to make,enum=A,enum=NS,enum=DS,enum=CNAME,enum=SOA,enum=PTR,enum=MX,enum=TXT,enum=AAAA",
	}
	for _, types := range GetSupportedDNSTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *DNSTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toDNSTypes(marshalledTypes)
	if err != nil {
		return err
	}

	holder.DNSType = computedType
	return nil
}

func (holder *DNSTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.DNSType.String())
}

func (holder DNSTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.DNSType.String(), nil
}
