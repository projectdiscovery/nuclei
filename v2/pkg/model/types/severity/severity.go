package severity

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"
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
	limit
)

var severityMappings = map[Severity]string{
	Info:     "info",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
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

//nolint:exported,revive //prefer to be explicit about the name, and make it refactor-safe
// Holder holds a Severity type. Required for un/marshalling purposes
type Holder struct {
	Severity Severity `mapping:"true"`
}

func (severityHolder Holder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "severity of the template",
		Description: "Seriousness of the implications of the template",
	}
	for _, severity := range GetSupportedSeverities() {
		gotType.Enum = append(gotType.Enum, severity.String())
	}
	return gotType
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

func (severityHolder *Holder) MarshalJSON() ([]byte, error) {
	return json.Marshal(severityHolder.Severity.String())
}

func (severityHolder Holder) MarshalYAML() (interface{}, error) {
	return severityHolder.Severity.String(), nil
}
