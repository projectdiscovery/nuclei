package dsl

import (
	"errors"
	"fmt"

	"github.com/projectdiscovery/nebula"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/deserialization"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/runtime"
)

type Options struct {
	Store *runtime.Store
}

var ErrDSLArguments = errors.New("invalid arguments provided to dsl")

func AddGlobalCustomHelpers(options *Options) error {
	_ = nebula.AddFunc("generate_java_gadget", func(args ...interface{}) (interface{}, error) {
		if len(args) != 3 {
			return nil, ErrDSLArguments
		}
		gadget := args[0].(string)
		cmd := args[1].(string)

		var encoding string
		if len(args) > 2 {
			encoding = args[2].(string)
		}
		data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
		return data, nil

	})

	_ = nebula.AddFunc("nuclei_vars_set", func(key string, value interface{}) {
		options.Store.Set(key, value)
	})

	_ = nebula.AddFunc("nuclei_vars_get", func(key string) (interface{}, error) {
		return options.Store.Get(key), nil
	})

	_ = nebula.AddFunc("nuclei_vars_del", func(key string) {
		options.Store.Del(key)
	})

	_ = nebula.AddFunc("nuclei_vars_len", func(args ...interface{}) int {
		return options.Store.Len()
	})

	_ = nebula.AddFunc("nuclei_vars_has", func(key string) bool {
		return options.Store.Has(key)
	})

	// for debug purposes - TODO: remove as nebula has implicit "print" operation
	_ = nebula.AddFunc("print_debug", func(args ...interface{}) (interface{}, error) {
		gologger.Info().Msgf("print_debug value: %s", fmt.Sprint(args))
		return true, nil
	})

	return nil
}

// AddHelperFunction allows creation of additional helper functions to be supported with templates
func AddHelperFunction(key string, f interface{}) error {
	return nebula.AddFunc(key, f)
}
