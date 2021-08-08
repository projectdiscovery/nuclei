package generators

import (
	"os"

	"github.com/projectdiscovery/stringsutil"
)

// EnvVars returns a map with all environment variables into a map
func EnvVars() map[string]interface{} {
	sliceEnvVars := os.Environ()
	envVars := make(map[string]interface{}, len(sliceEnvVars))
	for _, envVar := range sliceEnvVars {
		key, val := stringsutil.Before(envVar, "="), stringsutil.After(envVar, "=")
		envVars[key] = val
	}
	return envVars
}
