package generators

import (
	"os"
	"bufio"
	"strings"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func ReadVarsFromFile(path string) (map[string]interface{}, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	m := make(map[string]interface{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			m[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

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

	// merge with vars from a file
	if options.VarsFile != "" {
		vars, err := ReadVarsFromFile(options.VarsFile)
		if err == nil {
			m = MergeMaps(vars)
		}
	}
	return m
}
