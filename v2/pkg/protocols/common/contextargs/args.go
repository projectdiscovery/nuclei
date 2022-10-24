package contextargs

// Args is a generic map with helpers
type Args map[string]interface{}

// Set a key with value
func (args Args) Set(key string, value interface{}) {
	args[key] = value
}

// Get the value associated to a key
func (args Args) Get(key string) (interface{}, bool) {
	value, ok := args[key]
	return value, ok
}

// Has verifies if the map contains the key
func (args Args) Has(key string) bool {
	_, ok := args[key]
	return ok
}

// IsEmpty verifies if the map is empty
func (Args Args) IsEmpty() bool {
	return len(Args) == 0
}

// create a new args map instance
func newArgs() map[string]interface{} {
	return make(map[string]interface{})
}
