package label

import (
	"strings"
)

const (
	UnresolvedVariablesErrorLabel = "unresolved-variables-error"
)

var (
	ErrorLabels = []string{
		UnresolvedVariablesErrorLabel,
	}

	ErrorLableMap = map[string]struct {
		Name        string
		Description string
	}{
		"unv": {
			Name:        UnresolvedVariablesErrorLabel,
			Description: "Failed %v requests due to unresolved variables. Use -elabel=UNV to enable unresolved variables logs.",
		},
	}
)

// Contains checks if the error string contains any of the provided labels, if yes returns matched label and true
func Contains(errStr string, lables []string) (string, bool) {
	for _, label := range lables {
		if strings.Contains(errStr, label) {
			return label, true
		}
	}
	return "", false
}
