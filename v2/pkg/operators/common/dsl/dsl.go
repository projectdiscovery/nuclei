package dsl

import (
	"github.com/projectdiscovery/nebula"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/deserialization"
)

func AddCustomHelpers() error {
	return nebula.AddFunc("generate_java_gadget", func(args ...interface{}) (interface{}, error) {
		gadget := args[0].(string)
		cmd := args[1].(string)

		var encoding string
		if len(args) > 2 {
			encoding = args[2].(string)
		}
		data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
		return data, nil
	})
}
