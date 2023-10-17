package flow

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// ProtoOptions are options that can be passed to flow protocol callback
// ex: dns(protoOptions) <- protoOptions are optional and can be anything
type ProtoOptions struct {
	Hide      bool
	Async     bool
	protoName string
	reqIDS    []string
}

// Examples
//  dns() <- callback without any options
//  dns(1) or dns(1,3) <- callback with index of protocol in template request at 1 or  1 and 3
//  dns("probe-http") or dns("extract-vpc","probe-http") <- callback with id's instead of index of request in template
//  dns({hide:true}) or dns({hide:true,async:true}) <- callback with protocol options
//  hide - hides result/event from output & sdk
//  async - executes protocols in parallel (implicit wait no need to specify wait)
// Note: all of these options are optional and can be combined together in any order

// LoadOptions loads the protocol options from a map
func (P *ProtoOptions) LoadOptions(m map[string]interface{}) {
	P.Hide = GetBool(m["hide"])
	P.Async = GetBool(m["async"])
}

// GetBool returns bool value from interface
func GetBool(value interface{}) bool {
	if value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	default:
		tmpValue := types.ToString(value)
		if strings.EqualFold(tmpValue, "true") {
			return true
		}
	}
	return false
}
