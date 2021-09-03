package severity

import (
	"fmt"
	"strings"
)

type Severities []Severity

func (severities Severities) String() string {
	return strings.Join(severities.ToStringArray(), ", ")
}

func (severities *Severities) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledSeverities string
	if err := unmarshal(&marshalledSeverities); err != nil {
		return err
	}

	if err := severities.Set(marshalledSeverities); err != nil {
		return err
	}
	return nil
}

func (severities *Severities) Set(value string) error {
	inputSeverities := toStringSlice(value)

	for _, inputSeverity := range inputSeverities {
		if err := setSeverity(severities, inputSeverity); err != nil {
			return err
		}
	}

	return nil
}

func setSeverity(severities *Severities, value string) error {
	computedSeverity, err := toSeverity(value)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid severity", value)
	}

	// TODO change the Severities type to map[Severity]interface{}, where the values are struct{}{}, to "simulates" a "set" data structure
	*severities = append(*severities, computedSeverity)
	return nil
}

func (severities *Severities) ToStringArray() []string {
	var result []string
	for _, severity := range *severities {
		result = append(result, severity.String())
	}
	return result
}

func toStringSlice(value string) []string {
	var result []string
	if strings.Contains(value, ",") {
		slices := strings.Split(value, ",")
		result = append(result, slices...)
	} else {
		result = []string{value}
	}
	return result
}
