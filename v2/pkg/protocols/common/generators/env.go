package generators

import (
	"os"

	"github.com/projectdiscovery/stringsutil"
)

var envVars map[string]interface{}

func parseEnvVars() map[string]interface{} {
	sliceEnvVars := os.Environ()
	parsedEnvVars := make(map[string]interface{}, len(sliceEnvVars))
	for _, envVar := range sliceEnvVars {
		key, val := stringsutil.Before(envVar, "="), stringsutil.After(envVar, "=")
		parsedEnvVars[key] = val
	}
	return parsedEnvVars
}

// EnvVars returns a map with all environment variables into a map
func EnvVars() map[string]interface{} {
	if envVars == nil {
		envVars = parseEnvVars()
	}

	return envVars
}
