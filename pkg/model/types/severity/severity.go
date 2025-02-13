package severity

import (
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

type Severity int

// name:Severity
const (
	// name:undefined
	Undefined Severity = iota
	// name:info
	Info
	// name:low
	Low
	// name:medium
	Medium
	// name:high
	High
	// name:critical
	Critical
	// name:unknown
	Unknown
	limit
)

var severityMappings = map[Severity]string{
	Info:     "info",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
	Unknown:  "unknown",
}

func GetSupportedSeverities() Severities {
	var result []Severity
	for index := Severity(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toSeverity(valueToMap string) (Severity, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range severityMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid severity: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (severity Severity) String() string {
	return severityMappings[severity]
}

// Holder holds a Severity type. Required for un/marshalling purposes
//
//nolint:exported,revive //prefer to be explicit about the name, and make it refactor-safe
type Holder struct {
	Severity Severity `mapping:"true"`
}

// Implement a jsonschema for the severity holder
func (severityHolder Holder) JSONSchema() *jsonschema.Schema {
	enums := []interface{}{}
	for _, severity := range GetSupportedSeverities() {
		enums = append(enums, severity.String())
	}
	return &jsonschema.Schema{
		Type:        "string",
		Title:       "severity of the template",
		Description: "Seriousness of the implications of the template",
		Enum:        enums,
	}
}

func (severityHolder *Holder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledSeverity string
	if err := unmarshal(&marshalledSeverity); err != nil {
		return err
	}

	computedSeverity, err := toSeverity(marshalledSeverity)
	if err != nil {
		return err
	}

	severityHolder.Severity = computedSeverity
	return nil
}

func (severityHolder *Holder) UnmarshalJSON(data []byte) error {
	var marshalledSeverity string
	if err := json.Unmarshal(data, &marshalledSeverity); err != nil {
		return err
	}

	computedSeverity, err := toSeverity(marshalledSeverity)
	if err != nil {
		return err
	}

	severityHolder.Severity = computedSeverity
	return nil
}

func (severityHolder Holder) MarshalJSON() ([]byte, error) {
	return json.Marshal(severityHolder.Severity.String())
}

func (severityHolder Holder) MarshalYAML() (interface{}, error) {
	return severityHolder.Severity.String(), nil
}
