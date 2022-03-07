package engine

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/marker"
	"github.com/valyala/fasttemplate"
)

func replaceWithValues(data string, values map[string]interface{}) string {
	return fasttemplate.ExecuteStringStd(data, marker.ParenthesisOpen, marker.ParenthesisClose, values)
}
