// Inspired from https://github.com/ffuf/ffuf/blob/master/pkg/input/input.go

package generators

import (
	"github.com/pkg/errors"
	"maps"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// PayloadGenerator is the generator struct for generating payloads
type PayloadGenerator struct {
	Type     AttackType
	catalog  catalog.Catalog
	payloads map[string][]string
	options  *types.Options
}

// New creates a new generator structure for payload generation
func New(payloads map[string]interface{}, attackType AttackType, templatePath string, catalog catalog.Catalog, customAttackType string, opts *types.Options) (*PayloadGenerator, error) {
	if attackType.String() == "" {
		attackType = BatteringRamAttack
	}

	// Resolve payload paths if they are files.
	payloadsFinal := make(map[string]interface{})
	for payloadName, v := range payloads {
		switch value := v.(type) {
		case map[interface{}]interface{}:
			values, err := parsePayloadsWithAggression(payloadName, value, opts.FuzzAggressionLevel)
			if err != nil {
				return nil, errors.Wrap(err, "could not parse payloads with aggression")
			}
			maps.Copy(payloadsFinal, values)
		default:
			payloadsFinal[payloadName] = v
		}
	}

	generator := &PayloadGenerator{catalog: catalog, options: opts}
	if err := generator.validate(payloadsFinal, templatePath); err != nil {
		return nil, err
	}

	compiled, err := generator.loadPayloads(payloadsFinal, templatePath)
	if err != nil {
		return nil, err
	}
	generator.Type = attackType
	generator.payloads = compiled

	if customAttackType != "" {
		attackTypeNew, err := toAttackType(customAttackType)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse custom attack-type")
		}
		generator.Type = attackTypeNew
	}
	// Validate the batteringram payload set
	if attackType == BatteringRamAttack {
		if len(payloads) != 1 {
			return nil, errors.New("batteringram must have single payload set")
		}
	}
	return generator, nil
}

type aggressionLevelToPayloads struct {
	Low    []interface{}
	Medium []interface{}
	High   []interface{}
}

// parsePayloadsWithAggression parses the payloads with the aggression level
//
// Three agression are supported -
//   - low
//   - medium
//   - high
//
// low is the default level. If medium is specified, all templates from
// low and medium are executed. Similarly with high, including all templates
// from low, medium, high.
func parsePayloadsWithAggression(name string, v map[interface{}]interface{}, agression string) (map[string]interface{}, error) {
	payloadsLevels := &aggressionLevelToPayloads{}

	for k, v := range v {
		if _, ok := v.([]interface{}); !ok {
			return nil, errors.Errorf("only lists are supported for aggression levels payloads")
		}
		var ok bool
		switch k {
		case "low":
			payloadsLevels.Low, ok = v.([]interface{})
		case "medium":
			payloadsLevels.Medium, ok = v.([]interface{})
		case "high":
			payloadsLevels.High, ok = v.([]interface{})
		default:
			return nil, errors.Errorf("invalid aggression level %s specified for %s", k, name)
		}
		if !ok {
			return nil, errors.Errorf("invalid aggression level %s specified for %s", k, name)
		}
	}

	payloads := make(map[string]interface{})
	switch agression {
	case "low":
		payloads[name] = payloadsLevels.Low
	case "medium":
		payloads[name] = append(payloadsLevels.Low, payloadsLevels.Medium...)
	case "high":
		payloads[name] = append(payloadsLevels.Low, payloadsLevels.Medium...)
		payloads[name] = append(payloads[name].([]interface{}), payloadsLevels.High...)
	default:
		return nil, errors.Errorf("invalid aggression level %s specified for %s", agression, name)
	}
	return payloads, nil
}

// Iterator is a single instance of an iterator for a generator structure
type Iterator struct {
	Type        AttackType
	position    int
	msbIterator int
	total       int
	payloads    []*payloadIterator
}

// NewIterator creates a new iterator for the payloads generator
func (g *PayloadGenerator) NewIterator() *Iterator {
	var payloads []*payloadIterator

	for name, values := range g.payloads {
		payloads = append(payloads, &payloadIterator{name: name, values: values})
	}
	iterator := &Iterator{
		Type:     g.Type,
		payloads: payloads,
	}
	iterator.total = iterator.Total()
	return iterator
}

// Reset resets the iterator back to its initial value
func (i *Iterator) Reset() {
	i.position = 0
	i.msbIterator = 0

	for _, payload := range i.payloads {
		payload.resetPosition()
	}
}

// Remaining returns the amount of requests left for the generator.
func (i *Iterator) Remaining() int {
	return i.total - i.position
}

// Total returns the amount of input combinations available
func (i *Iterator) Total() int {
	count := 0
	switch i.Type {
	case BatteringRamAttack:
		for _, p := range i.payloads {
			count += len(p.values)
		}
	case PitchForkAttack:
		count = len(i.payloads[0].values)
		for _, p := range i.payloads {
			if count > len(p.values) {
				count = len(p.values)
			}
		}
	case ClusterBombAttack:
		count = 1
		for _, p := range i.payloads {
			count *= len(p.values)
		}
	}
	return count
}

// Value returns the next value for an iterator
func (i *Iterator) Value() (map[string]interface{}, bool) {
	switch i.Type {
	case BatteringRamAttack:
		return i.batteringRamValue()
	case PitchForkAttack:
		return i.pitchforkValue()
	case ClusterBombAttack:
		return i.clusterbombValue()
	default:
		return i.batteringRamValue()
	}
}

// batteringRamValue returns a list of all payloads for the iterator
func (i *Iterator) batteringRamValue() (map[string]interface{}, bool) {
	values := make(map[string]interface{}, 1)

	currentIndex := i.msbIterator
	payload := i.payloads[currentIndex]
	if !payload.next() {
		i.msbIterator++
		if i.msbIterator == len(i.payloads) {
			return nil, false
		}
		return i.batteringRamValue()
	}
	values[payload.name] = payload.value()
	payload.incrementPosition()
	i.position++
	return values, true
}

// pitchforkValue returns a map of keyword:value pairs in same index
func (i *Iterator) pitchforkValue() (map[string]interface{}, bool) {
	values := make(map[string]interface{}, len(i.payloads))

	for _, p := range i.payloads {
		if !p.next() {
			return nil, false
		}
		values[p.name] = p.value()
		p.incrementPosition()
	}
	i.position++
	return values, true
}

// clusterbombValue returns a combination of all input pairs in key:value format.
func (i *Iterator) clusterbombValue() (map[string]interface{}, bool) {
	if i.position >= i.total {
		return nil, false
	}
	values := make(map[string]interface{}, len(i.payloads))

	// Should we signal the next InputProvider in the slice to increment
	signalNext := false
	first := true
	for index, p := range i.payloads {
		if signalNext {
			p.incrementPosition()
			signalNext = false
		}
		if !p.next() {
			// No more inputs in this input provider
			if index == i.msbIterator {
				// Reset all previous wordlists and increment the msb counter
				i.msbIterator++
				i.clusterbombIteratorReset()
				// Start again
				return i.clusterbombValue()
			}
			p.resetPosition()
			signalNext = true
		}
		values[p.name] = p.value()
		if first {
			p.incrementPosition()
			first = false
		}
	}
	i.position++
	return values, true
}

func (i *Iterator) clusterbombIteratorReset() {
	for index, p := range i.payloads {
		if index < i.msbIterator {
			p.resetPosition()
		}
		if index == i.msbIterator {
			p.incrementPosition()
		}
	}
}

// payloadIterator is a single instance of an iterator for a single payload list.
type payloadIterator struct {
	index  int
	name   string
	values []string
}

// next returns true if there are more values in payload iterator
func (i *payloadIterator) next() bool {
	return i.index < len(i.values)
}

// resetPosition resets the position of the payload iterator
func (i *payloadIterator) resetPosition() {
	i.index = 0
}

// incrementPosition increments the position of the payload iterator
func (i *payloadIterator) incrementPosition() {
	i.index++
}

// value returns the value of the payload at an index
func (i *payloadIterator) value() string {
	return i.values[i.index]
}
