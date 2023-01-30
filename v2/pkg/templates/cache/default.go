package cache

var (
	// Unmarshaled cache of unmarsheled templates to bare struct
	Unmarshaled *Templates
	// Compiled cache of templates (with all options and clients allocated for the running session)
	Compiled *Templates
)

func init() {
	Unmarshaled = New()
	Compiled = New()
}

// Clear templates cache
func Clear() {
	Unmarshaled.Clear()
	Compiled.Clear()
}
