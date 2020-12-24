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
	// Sniper replaces each variables with values at a time.
	Sniper Type = iota + 1
	// PitchFork replaces variables with positional value from multiple wordlists
	PitchFork
	// ClusterBomb replaces variables with all possible combinations of values
	ClusterBomb
)

// StringToType is an table for conversion of attack type from string.
var StringToType = map[string]Type{
	"sniper":      Sniper,
	"pitchfork":   PitchFork,
	"clusterbomb": ClusterBomb,
}

// New creates a new generator structure for payload generation
func New(payloads map[string]interface{}, Type Type) (*Generator, error) {
	compiled, err := loadPayloads(payloads)
	if err != nil {
		return nil, err
	}
	return &Generator{Type: Type, payloads: compiled}, nil
}

// Iterator is a single instance of an iterator for a generator structure
type Iterator struct {
	Type        Type
	position    int
	msbIterator int
	payloads    []*payloadIterator
}

// NewIterator creates a new iterator for the payloads generator
func (g *Generator) NewIterator() *Iterator {
	var payloads []*payloadIterator

	for name, values := range g.payloads {
		payloads = append(payloads, &payloadIterator{name: name, values: values})
	}
	return &Iterator{Type: g.Type, payloads: payloads}
}

// Next returns true if there are more inputs in iterator
func (i *Iterator) Next() bool {
	if i.position >= i.Total() {
		return false
	}
	i.position++
	return true
}

//Total returns the amount of input combinations available
func (i *Iterator) Total() int {
	count := 0
	switch i.Type {
	case Sniper:
		for _, p := range i.payloads {
			if p.Total() > count {
				count = p.Total()
			}
		}
	case PitchFork:
		for _, p := range i.payloads {
			if p.Total() > count {
				count = p.Total()
			}
		}
	case ClusterBomb:
		count = 1
		for _, p := range i.payloads {
			count = count * p.Total()
		}
	}
	return count
}

// Value returns the next value for an iterator
func (i *Iterator) Value() map[string]interface{} {
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
func (i *Iterator) sniperValue() map[string]interface{} {
	values := make(map[string]interface{}, len(i.payloads))

	for _, p := range i.payloads {
		if !p.Next() {
			p.ResetPosition()
		}
		values[p.name] = p.Value()
		p.IncrementPosition()
	}
	return values
}

// pitchforkValue returns a map of keyword:value pairs in same index
func (i *Iterator) pitchforkValue() map[string]interface{} {
	values := make(map[string]interface{}, len(i.payloads))

	for _, p := range i.payloads {
		if !p.Next() {
			p.ResetPosition()
		}
		values[p.name] = p.Value()
		p.IncrementPosition()
	}
	return values
}

// clusterbombValue returns a combination of all input pairs in key:value format.
func (i *Iterator) clusterbombValue() map[string]interface{} {
	values := make(map[string]interface{}, len(i.payloads))

	// Should we signal the next InputProvider in the slice to increment
	signalNext := false
	first := true
	for index, p := range i.payloads {
		if signalNext {
			p.IncrementPosition()
			signalNext = false
		}
		if !p.Next() {
			// No more inputs in this inputprovider
			if index == i.msbIterator {
				// Reset all previous wordlists and increment the msb counter
				i.msbIterator++
				i.clusterbombIteratorReset()
				// Start again
				return i.clusterbombValue()
			}
			p.ResetPosition()
			signalNext = true
		}
		values[p.name] = p.Value()
		if first {
			p.IncrementPosition()
			first = false
		}
	}
	return values
}

func (i *Iterator) clusterbombIteratorReset() {
	for index, p := range i.payloads {
		if index < i.msbIterator {
			p.ResetPosition()
		}
		if index == i.msbIterator {
			p.IncrementPosition()
		}
	}
}

// payloadIterator is a single instance of an iterator for a single payload list.
type payloadIterator struct {
	index  int
	name   string
	values []string
}

// Next returns true if there are more values in payload iterator
func (i *payloadIterator) Next() bool {
	if i.index >= i.Total() {
		return false
	}
	return true
}

func (i *payloadIterator) ResetPosition() {
	i.index = 0
}

func (i *payloadIterator) IncrementPosition() {
	i.index++
}

func (i *payloadIterator) Value() string {
	value := i.values[i.index]
	return value
}

func (i *payloadIterator) Total() int {
	return len(i.values)
}
