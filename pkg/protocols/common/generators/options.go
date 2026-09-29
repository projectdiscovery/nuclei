package generators

import (
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// optionsPayloadMap caches the result of BuildPayloadFromOptions per options
// pointer. This supports multiple SDK instances with different options running
// concurrently.
var optionsPayloadMap sync.Map // map[*types.Options]map[string]interface{}

// BuildPayloadFromOptions returns a map with the payloads provided via CLI.
//
// The result is cached per options pointer since options don't change during a run.
// Returns a copy of the cached map to prevent concurrent modification issues.
// Safe for concurrent use with multiple SDK instances.
func BuildPayloadFromOptions(options *types.Options) map[string]interface{} {
	if options == nil {
		return make(map[string]interface{})
	}

	if cached, ok := optionsPayloadMap.Load(options); ok {
		return CopyMap(cached.(map[string]interface{}))
	}

	m := make(map[string]interface{})

	// merge with vars
	if !options.Vars.IsEmpty() {
		m = MergeMaps(m, options.Vars.AsMap())
	}

	// merge with env vars
	if options.EnvironmentVariables {
		m = MergeMaps(EnvVars(), m)
	}

	actual, _ := optionsPayloadMap.LoadOrStore(options, m)

	// Return a copy to prevent concurrent writes to the cached map
	return CopyMap(actual.(map[string]interface{}))
}

// ClearOptionsPayloadMap clears the cached options payload.
// SDK users should call this when disposing of a NucleiEngine instance
// to prevent memory leaks if creating many short-lived instances.
func ClearOptionsPayloadMap(options *types.Options) {
	if options != nil {
		optionsPayloadMap.Delete(options)
	}
}
