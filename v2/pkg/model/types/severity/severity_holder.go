package severity

import (
	"encoding/json"

	"github.com/alecthomas/jsonschema"
)

// Holder holds a Severity type. Required for un/marshalling purposes
type Holder struct {
	Severity Severity
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
