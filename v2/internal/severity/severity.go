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
)

var severityMappings = map[Severity]string{
	Info:     "info",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

type SeverityStruct struct {
	Key Severity
}

func toSeverity(valueToMap string) (Severity, error) {
	for key, currentValue := range severityMappings {
		if normalizeValue(valueToMap) == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid severity: " + valueToMap)
}

func GetSupportedSeverities() []Severity {
	var result []Severity
	for key := range severityMappings {
		result = append(result, key)
	}
	return result
}

func (severity SeverityStruct) MarshalYAML() (interface{}, error) {
	if value, found := severityMappings[severity.Key]; found {
		return &struct{ Key string }{value}, nil
	} else {
		panic("Invalid field to marshall")
	}
}

func (severity SeverityStruct) MarshalJSON() ([]byte, error) {
	if value, found := severityMappings[severity.Key]; found {
		return json.Marshal(&struct{ Key string }{value})
	} else {
		panic("Invalid field to marshall")
	}
}

func (severity *SeverityStruct) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var objMap map[string]string
	if err := unmarshal(&objMap); err != nil {
		return err
	}

	return mapToSeverity(objMap, severity)
}

func mapToSeverity(objMap map[string]string, severity *SeverityStruct) error {
	stringSeverity := getFirstElement(objMap)
	if readableSeverity, err := toSeverity(stringSeverity); err == nil {
		severity = &SeverityStruct{readableSeverity}
		return nil
	} else {
		return err
	}
}

func (severity *SeverityStruct) UnmarshalJSON(data []byte) error {
	var objMap map[string]string
	if err := json.Unmarshal(data, &objMap); err != nil {
		return err
	}

	return mapToSeverity(objMap, severity)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func getFirstElement(stringMap map[string]string) string {
	var result string
	for _, value := range stringMap {
		result = value
		break
	}
	return result
}

/* Alternative implementation
func (severity *SeverityStruct) UnmarshalJSON(data []byte) error {
	var objMap map[string]*json.RawMessage
	if err := json.Unmarshal(data, &objMap); err != nil {
		return err
	}
	severityStructFirstFieldName := reflect.Indirect(reflect.ValueOf(severity)).Type().Field(0).Name

	var stringSeverity string
	if err := json.Unmarshal(*objMap[severityStructFirstFieldName], &stringSeverity); err != nil {
		return err
	}

	if readableSeverity, err := toSeverity(stringSeverity); err == nil {
		severity = &SeverityStruct{readableSeverity}
		return nil
	} else {
		return err
	}
}*/

func (severity Severity) normalize() string {
	return strings.TrimSpace(strings.ToLower(severity.String()))
}

func (severity Severity) String() string {
	return severityMappings[severity]
}
