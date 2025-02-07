package generators

import (
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// AttackType is the type of attack for payloads
type AttackType int

// Supported values for the AttackType
// name:AttackType
const (
	// name:batteringram
	BatteringRamAttack AttackType = iota + 1
	// name:pitchfork
	PitchForkAttack
	// name:clusterbomb
	ClusterBombAttack
	limit
)

// attackTypeMappings is a table for conversion of attack type from string.
var attackTypeMappings = map[AttackType]string{
	BatteringRamAttack: "batteringram",
	PitchForkAttack:    "pitchfork",
	ClusterBombAttack:  "clusterbomb",
}

func GetSupportedAttackTypes() []AttackType {
	var result []AttackType
	for index := AttackType(1); index < limit; index++ {
		result = append(result, index)
	}
	return result
}

func toAttackType(valueToMap string) (AttackType, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range attackTypeMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("invalid attack type: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (t AttackType) String() string {
	return attackTypeMappings[t]
}

// AttackTypeHolder is used to hold internal type of the protocol
type AttackTypeHolder struct {
	Value AttackType `mapping:"true"`
}

func (holder AttackTypeHolder) JSONSchema() *jsonschema.Schema {
	gotType := &jsonschema.Schema{
		Type:        "string",
		Title:       "type of the attack",
		Description: "Type of the attack",
	}
	for _, types := range GetSupportedAttackTypes() {
		gotType.Enum = append(gotType.Enum, types.String())
	}
	return gotType
}

func (holder *AttackTypeHolder) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var marshalledTypes string
	if err := unmarshal(&marshalledTypes); err != nil {
		return err
	}

	computedType, err := toAttackType(marshalledTypes)
	if err != nil {
		return err
	}

	holder.Value = computedType
	return nil
}

func (holder *AttackTypeHolder) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" {
		return nil
	}
	computedType, err := toAttackType(s)
	if err != nil {
		return err
	}

	holder.Value = computedType
	return nil
}

func (holder *AttackTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.Value.String())
}

func (holder AttackTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.Value.String(), nil
}
