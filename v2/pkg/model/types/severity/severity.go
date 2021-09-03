package severity

import (
	"strings"

	"github.com/pkg/errors"
)

type Severity int

const (
	Undefined Severity = iota
	Info
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
