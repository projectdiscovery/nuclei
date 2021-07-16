package severity

import (
	"encoding/json"
	"github.com/pkg/errors"
	"strings"
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

func (severity Severity) normalize() string {
	return normalizeValue(severity.String())
}

func (severity Severity) String() string {
	return severityMappings[severity]
}

type SeverityHolder struct {
	Severity Severity
}

func (severityHolder SeverityHolder) MarshalYAML() (interface{}, error) {
	if value, found := severityMappings[severityHolder.Severity]; found {
		return &struct{ Severity string }{value}, nil // TODO see if the new struct can be dynamically created using reflection to make it refactor safe
	} else {
		panic("Invalid field to marshall")
	}
}

func (severityHolder SeverityHolder) MarshalJSON() ([]byte, error) {
	if value, found := severityMappings[severityHolder.Severity]; found {
		return json.Marshal(&struct{ Severity string }{value}) // TODO see if the new struct can be dynamically created using reflection to make it refactor safe
	} else {
		panic("Invalid field to marshall")
	}
}

func (severityHolder *SeverityHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledSeverity map[string]string
	if err := unmarshal(&marshalledSeverity); err != nil {
		return err
	}

	computedSeverity, err := toSeverity(getFirstValue(marshalledSeverity))
	if err != nil {
		return err
	}

	severityHolder.Severity = computedSeverity
	return nil
}

func (severityHolder *SeverityHolder) UnmarshalJSON(data []byte) error {
	var objMap map[string]string
	if err := json.Unmarshal(data, &objMap); err != nil {
		return err
	}

	return mapToSeverity(objMap, severityHolder)
}

func mapToSeverity(objMap map[string]string, severity *SeverityHolder) error {
	if len(objMap) != 1 {
		return errors.New("There can only be one severity defined")
	}
	stringSeverity := getFirstValue(objMap)
	if readableSeverity, err := toSeverity(stringSeverity); err == nil {
		severity = &SeverityHolder{readableSeverity}
		return nil
	} else {
		return err
	}
}

func getFirstValue(stringMap map[string]string) string {
	var result string
	for _, value := range stringMap {
		result = value
		break
	}
	return result
}
