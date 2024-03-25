package runner

import (
	"os"
	"reflect"
	"strings"
)

// expandEndVars looks for values in a struct tagged with "yaml" and checks if they are prefixed with '$'.
// If they are, it will try to retrieve the value from the environment and if it exists, it will set the
// value of the field to that of the environment variable.
func expandEndVars(f reflect.Value, fieldType reflect.StructField) {
	if _, ok := fieldType.Tag.Lookup("yaml"); !ok {
		return
	}
	if f.Kind() == reflect.String {
		str := f.String()
		if strings.HasPrefix(str, "$") {
			env := strings.TrimPrefix(str, "$")
			retrievedEnv := os.Getenv(env)
			if retrievedEnv != "" {
				f.SetString(os.Getenv(env))
			}
		}
	}
}
