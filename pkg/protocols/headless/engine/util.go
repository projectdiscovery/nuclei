package engine

import (
	"github.com/projectdiscovery/fasttemplate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
)

// replaceWithValues replaces the template markers with the values
//
// Deprecated: Not used anymore.
// nolint: unused
func replaceWithValues(data string, values map[string]interface{}) string {
	return fasttemplate.ExecuteStringStd(data, marker.ParenthesisOpen, marker.ParenthesisClose, values)
}

func getExpressions(data string, values map[string]interface{}) []string {
	return expressions.FindExpressions(data, marker.ParenthesisOpen, marker.ParenthesisClose, values)
}
