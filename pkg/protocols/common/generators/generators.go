// Inspired from https://github.com/ffuf/ffuf/blob/master/pkg/input/input.go

package generators

import (
	"maps"
	"math/rand"

	"github.com/pkg/errors"

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
// Three aggression are supported -
//   - low
//   - medium
//   - high
//
// low is the default level. If medium is specified, all templates from
// low and medium are executed. Similarly with high, including all templates
// from low, medium, high.
func parsePayloadsWithAggression(name string, v map[interface{}]interface{}, aggression string) (map[string]interface{}, error) {
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
	switch aggression {
	case "low":
		payloads[name] = payloadsLevels.Low
	case "medium":
		payloads[name] = append(payloadsLevels.Low, payloadsLevels.Medium...)
	case "high":
		payloads[name] = append(payloadsLevels.Low, payloadsLevels.Medium...)
		payloads[name] = append(payloads[name].([]interface{}), payloadsLevels.High...)
	default:
		return nil, errors.Errorf("invalid aggression level %s specified for %s", aggression, name)
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
	// perm, when non-nil, maps the visit position to a shuffled combination
	// index in [0,total). It is set when payloads are iterated in a random
	// order instead of the sequential order of the payload sets, and uses
	// O(1) memory instead of materialising the whole index space.
	perm *randomPermutation
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
	if g.options != nil && g.options.PayloadRandomOrder && iterator.total > 1 {
		iterator.perm = newRandomPermutation(iterator.total)
	}
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
	if i.perm != nil {
		return i.randomValue()
	}
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

// randomValue returns the combination at the next index of the shuffled order.
// It visits every combination exactly once, like the sequential iteration, but
// in a random order.
func (i *Iterator) randomValue() (map[string]interface{}, bool) {
	if i.position >= i.total {
		return nil, false
	}
	values := i.valueAt(i.perm.at(i.position))
	i.position++
	return values, true
}

// valueAt returns the combination of payloads at the given combination index,
// counted the same way Total counts combinations for the attack type.
func (i *Iterator) valueAt(index int) map[string]interface{} {
	switch i.Type {
	case PitchForkAttack:
		values := make(map[string]interface{}, len(i.payloads))
		for _, p := range i.payloads {
			values[p.name] = p.values[index]
		}
		return values
	case ClusterBombAttack:
		values := make(map[string]interface{}, len(i.payloads))
		remaining := index
		for _, p := range i.payloads {
			size := len(p.values)
			values[p.name] = p.values[remaining%size]
			remaining /= size
		}
		return values
	default: // BatteringRamAttack
		values := make(map[string]interface{}, 1)
		for _, p := range i.payloads {
			if index < len(p.values) {
				values[p.name] = p.values[index]
				break
			}
			index -= len(p.values)
		}
		return values
	}
}

// randomPermutation is a pseudo-random permutation of the combination indices
// [0,total). It yields every index exactly once in a shuffled order using O(1)
// memory, so the whole index space is never materialised. The permutation is a
// small Feistel network over the smallest power-of-two domain that covers the
// range, restricted to [0,total) by cycle-walking. It is seeded once per
// iterator, so walking the same positions again (after Reset) replays the same
// order.
type randomPermutation struct {
	total int
	half  uint
	mask  uint64
	key   uint64
}

// newRandomPermutation seeds a permutation of [0,total). The caller guarantees
// total > 1.
func newRandomPermutation(total int) *randomPermutation {
	bits := uint(0)
	for bits < 63 && uint64(1)<<bits < uint64(total) {
		bits++
	}
	if bits%2 != 0 {
		// a balanced Feistel needs an even bit width for its two halves
		bits++
	}
	return &randomPermutation{
		total: total,
		half:  bits / 2,
		mask:  uint64(1)<<(bits/2) - 1,
		key:   rand.Uint64(),
	}
}

// at returns the combination index visited at the given position. As position
// runs over [0,total) the results are a permutation of [0,total).
func (p *randomPermutation) at(position int) int {
	x := uint64(position)
	for {
		x = p.encrypt(x)
		if x < uint64(p.total) {
			return int(x)
		}
	}
}

// encrypt applies the Feistel network, a bijection over the power-of-two
// domain, so every input maps to a distinct output.
func (p *randomPermutation) encrypt(x uint64) uint64 {
	left := x >> p.half & p.mask
	right := x & p.mask
	for round := uint64(0); round < 4; round++ {
		left, right = right, left^(p.round(round, right)&p.mask)
	}
	return left<<p.half | right
}

// round is the Feistel round function: a keyed mix of the round number and the
// right half. Its output quality only affects how shuffled the order looks, not
// that every index is visited once.
func (p *randomPermutation) round(round, right uint64) uint64 {
	h := right ^ (p.key + round*0x9e3779b97f4a7c15)
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
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
