package generators

import (
	"encoding/json"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/pkg/errors"
)

// AttackType is the type of attack for payloads
type AttackType int

// Supported values for the ProtocolType
const (
	// BatteringRamAttack replaces same payload in all the defined payload positions at once
	BatteringRamAttack AttackType = iota + 1
	// PitchForkAttack replaces variables with positional value from multiple wordlists
	PitchForkAttack
	// ClusterBombAttack replaces variables with all possible combinations of values
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
	Value AttackType
}

func (holder AttackTypeHolder) JSONSchemaType() *jsonschema.Type {
	gotType := &jsonschema.Type{
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

func (holder *AttackTypeHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(holder.Value.String())
}

func (holder AttackTypeHolder) MarshalYAML() (interface{}, error) {
	return holder.Value.String(), nil
}
