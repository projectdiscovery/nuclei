// Inspired from https://github.com/ffuf/ffuf/blob/master/pkg/input/input.go

package generators

// Generator is the generator struct for generating payloads
type Generator struct {
	Type     Type
	payloads map[string][]string
}

// Type is type of attack
type Type int

const (
	// Sniper replaces each variable with values at a time.
	Sniper Type = iota + 1
	// PitchFork replaces variables with positional value from multiple wordlists
	PitchFork
	// ClusterBomb replaces variables with all possible combinations of values
	ClusterBomb
)

// StringToType is a table for conversion of attack type from string.
var StringToType = map[string]Type{
	"sniper":      Sniper,
	"pitchfork":   PitchFork,
	"clusterbomb": ClusterBomb,
}

// New creates a new generator structure for payload generation
func New(payloads map[string]interface{}, payloadType Type, templatePath string) (*Generator, error) {
	generator := &Generator{}
	if err := generator.validate(payloads, templatePath); err != nil {
		return nil, err
	}

	compiled, err := loadPayloads(payloads)
	if err != nil {
		return nil, err
	}
	generator.Type = payloadType
	generator.payloads = compiled

	return generator, nil
}

// Iterator is a single instance of an iterator for a generator structure
type Iterator struct {
	Type        Type
	position    int
	msbIterator int
	total       int
	payloads    []*payloadIterator
}

// NewIterator creates a new iterator for the payloads generator
func (g *Generator) NewIterator() *Iterator {
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
	case Sniper:
		for _, p := range i.payloads {
			count += len(p.values)
		}
	case PitchFork:
		count = len(i.payloads[0].values)
		for _, p := range i.payloads {
			if count > len(p.values) {
				count = len(p.values)
			}
		}
	case ClusterBomb:
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
	case Sniper:
		return i.sniperValue()
	case PitchFork:
		return i.pitchforkValue()
	case ClusterBomb:
		return i.clusterbombValue()
	default:
		return i.sniperValue()
	}
}

// sniperValue returns a list of all payloads for the iterator
func (i *Iterator) sniperValue() (map[string]interface{}, bool) {
	values := make(map[string]interface{}, 1)

	currentIndex := i.msbIterator
	payload := i.payloads[currentIndex]
	if !payload.next() {
		i.msbIterator++
		if i.msbIterator == len(i.payloads) {
			return nil, false
		}
		return i.sniperValue()
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
			// No more inputs in this inputprovider
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
