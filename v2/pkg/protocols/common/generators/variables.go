package generators

import "github.com/projectdiscovery/nuclei/v2/pkg/types"

// Merge the variables to the map of values
func MergeVariables(values map[string]interface{}, options *types.Options) map[string]interface{} {
	// merge with global vars if any
	if !options.Vars.IsEmpty() {
		values = MergeMaps(values, options.Vars.AsMap())
	}

	// merge with env vars
	if options.EnvironmentVariables {
		values = MergeMaps(EnvVars(), values)
	}

	return values
}
