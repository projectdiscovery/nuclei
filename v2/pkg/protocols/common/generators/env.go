package generators

import (
	"os"

	"github.com/projectdiscovery/stringsutil"
)

var envVars map[string]interface{}

func init() {
	// snapshot env vars at bootstrap
	envVars = parseEnvVars()
}

func parseEnvVars() map[string]interface{} {
	sliceEnvVars := os.Environ()
	envVars := make(map[string]interface{}, len(sliceEnvVars))
	for _, envVar := range sliceEnvVars {
		key, val := stringsutil.Before(envVar, "="), stringsutil.After(envVar, "=")
		envVars[key] = val
	}
	return envVars
}

// EnvVars returns a map with all environment variables into a map
func EnvVars() map[string]interface{} {
	if envVars == nil {
		envVars = parseEnvVars()
	}

	return envVars
}
