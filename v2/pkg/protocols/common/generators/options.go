package generators

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// BuildPayloadFromOptions returns a map with the payloads provided via CLI
func BuildPayloadFromOptions(options *types.Options) map[string]interface{} {
	m := make(map[string]interface{})
	// merge with vars
	if !options.Vars.IsEmpty() {
		m = MergeMaps(m, options.Vars.AsMap())
	}

	// merge with env vars
	if options.EnvironmentVariables {
		m = MergeMaps(EnvVars(), m)
	}
	return m
}
