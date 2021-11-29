package severity

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

// Severities used by the goflags library for parsing an array of Severity types, passed as CLI arguments from the user
type Severities []Severity

func (severities *Severities) Set(values string) error {
	inputSeverities, err := goflags.ToNormalizedStringSlice(values)
	if err != nil {
		return err
	}

	for _, inputSeverity := range inputSeverities {
		if err := setSeverity(severities, inputSeverity); err != nil {
			return err
		}
	}
	return nil
}

func (severities *Severities) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var stringSliceValue stringslice.StringSlice
	if err := unmarshal(&stringSliceValue); err != nil {
		return err
	}

	stringSLice := stringSliceValue.ToSlice()
	var result = make(Severities, 0, len(stringSLice))
	for _, severityString := range stringSLice {
		if err := setSeverity(&result, severityString); err != nil {
			return err
		}
	}
	*severities = result
	return nil
}

func (severities Severities) String() string {
	var stringSeverities = make([]string, 0, len(severities))
	for _, severity := range severities {
		stringSeverities = append(stringSeverities, severity.String())
	}
	return strings.Join(stringSeverities, ", ")
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
