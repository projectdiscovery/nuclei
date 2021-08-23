package severity

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
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

func toSeverity(valueToMap string) (Severity, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range severityMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid severity: " + valueToMap)
}

func GetSupportedSeverities() Severities {
	var result []Severity
	for index := Severity(0); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (severity Severity) String() string {
	return severityMappings[severity]
}

//nolint:exported,revive //prefer to be explicit about the name, and make it refactor-safe
type SeverityHolder struct {
	Severity Severity
}

func (severityHolder SeverityHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
		Type:        "string",
		Title:       "severity of the template",
		Description: "Seriousness of the implications of the template",
		Enum:        []interface{}{Info.String(), Low.String(), Medium.String(), High.String(), Critical.String()},
	}
	return gotType
}

func (severityHolder *SeverityHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
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

func (severityHolder *SeverityHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(severityHolder.Severity.String())
}

func (severityHolder SeverityHolder) MarshalYAML() (interface{}, error) {
	return severityHolder.Severity.String(), nil
}
