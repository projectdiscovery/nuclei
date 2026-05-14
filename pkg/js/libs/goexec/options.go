package goexec

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	DefaultOutputMethod  = "smb"
	DefaultOutputTimeout = 60
	DefaultMaxOutputSize = 1024 * 1024
)

// ExecutionOptions controls one Windows execution helper call.
type ExecutionOptions struct {
	Timeout        int
	Proxy          string
	Output         bool
	OutputMethod   string
	OutputTimeout  int
	NoDeleteOutput bool
	Directory      string
	Endpoint       string
	EPM            bool
	EPMFilter      string
	NoSign         bool
	NoSeal         bool
	MaxOutputSize  int
}

// DefaultExecutionOptions returns conservative defaults for helper execution.
func DefaultExecutionOptions() ExecutionOptions {
	return ExecutionOptions{
		OutputMethod:  DefaultOutputMethod,
		OutputTimeout: DefaultOutputTimeout,
		Directory:     `C:\`,
		MaxOutputSize: DefaultMaxOutputSize,
	}
}

// MergeOptions combines base options with a JavaScript-supplied object.
func MergeOptions(base ExecutionOptions, raw interface{}) ExecutionOptions {
	if base.OutputMethod == "" {
		base.OutputMethod = DefaultOutputMethod
	}
	if base.OutputTimeout <= 0 {
		base.OutputTimeout = DefaultOutputTimeout
	}
	if base.Directory == "" {
		base.Directory = `C:\`
	}
	if base.MaxOutputSize <= 0 {
		base.MaxOutputSize = DefaultMaxOutputSize
	}

	if raw == nil {
		return base
	}
	if opts, ok := raw.(*ExecutionOptions); ok && opts != nil {
		return mergeStruct(base, *opts)
	}
	if opts, ok := raw.(ExecutionOptions); ok {
		return mergeStruct(base, opts)
	}

	values := mapFromAny(raw)
	if values == nil {
		return base
	}
	if v, ok := intValue(values, "timeout"); ok {
		base.Timeout = v
	}
	if v := stringValue(values, "proxy"); v != "" {
		base.Proxy = v
	}
	if v, ok := boolValue(values, "output"); ok {
		base.Output = v
	}
	if v := stringValue(values, "outputMethod", "output_method", "outMethod", "out_method"); v != "" {
		base.OutputMethod = strings.ToLower(v)
	}
	if v, ok := intValue(values, "outputTimeout", "output_timeout", "outTimeout", "out_timeout"); ok {
		base.OutputTimeout = v
	}
	if v, ok := boolValue(values, "noDeleteOutput", "no_delete_output", "noDeleteOut", "no_delete_out"); ok {
		base.NoDeleteOutput = v
	}
	if v := stringValue(values, "directory", "workingDirectory", "working_directory"); v != "" {
		base.Directory = v
	}
	if v := stringValue(values, "endpoint"); v != "" {
		base.Endpoint = v
	}
	if v, ok := boolValue(values, "epm", "EPM"); ok {
		base.EPM = v
	}
	if v := stringValue(values, "epmFilter", "epm_filter", "filter"); v != "" {
		base.EPMFilter = v
	}
	if v, ok := boolValue(values, "noSign", "no_sign"); ok {
		base.NoSign = v
	}
	if v, ok := boolValue(values, "noSeal", "no_seal"); ok {
		base.NoSeal = v
	}
	if v, ok := intValue(values, "maxOutputSize", "max_output_size"); ok {
		base.MaxOutputSize = v
	}
	return base
}

// mergeStruct overlays non-zero fields from opts on top of base.
//
// Boolean fields are one-way: a `true` in opts sets the corresponding base
// field to true, but a `false` is treated as "unset" (because a Go struct has
// no way to distinguish unset from a literal false) and therefore leaves the
// base value alone. Callers that need to flip a true base back to false must
// either mutate the base struct directly or use the map-based merge path
// (where key presence is meaningful).
func mergeStruct(base, opts ExecutionOptions) ExecutionOptions {
	if opts.Timeout != 0 {
		base.Timeout = opts.Timeout
	}
	if opts.Proxy != "" {
		base.Proxy = opts.Proxy
	}
	if opts.Output {
		base.Output = opts.Output
	}
	if opts.OutputMethod != "" {
		base.OutputMethod = strings.ToLower(opts.OutputMethod)
	}
	if opts.OutputTimeout != 0 {
		base.OutputTimeout = opts.OutputTimeout
	}
	if opts.NoDeleteOutput {
		base.NoDeleteOutput = opts.NoDeleteOutput
	}
	if opts.Directory != "" {
		base.Directory = opts.Directory
	}
	if opts.Endpoint != "" {
		base.Endpoint = opts.Endpoint
	}
	if opts.EPM {
		base.EPM = opts.EPM
	}
	if opts.EPMFilter != "" {
		base.EPMFilter = opts.EPMFilter
	}
	if opts.NoSign {
		base.NoSign = opts.NoSign
	}
	if opts.NoSeal {
		base.NoSeal = opts.NoSeal
	}
	if opts.MaxOutputSize != 0 {
		base.MaxOutputSize = opts.MaxOutputSize
	}
	return base
}

func mapFromAny(raw interface{}) map[string]interface{} {
	switch value := raw.(type) {
	case nil:
		return nil
	case map[string]interface{}:
		return value
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(value))
		for k, v := range value {
			out[fmt.Sprint(k)] = v
		}
		return out
	default:
		return nil
	}
}

func stringValue(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				return typed
			case fmt.Stringer:
				return typed.String()
			}
			if value != nil {
				return fmt.Sprint(value)
			}
		}
	}
	return ""
}

func boolValue(values map[string]interface{}, keys ...string) (bool, bool) {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			parsed, err := strconv.ParseBool(typed)
			return parsed, err == nil
		}
	}
	return false, false
}

func intValue(values map[string]interface{}, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed, true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case string:
			parsed, err := strconv.Atoi(typed)
			return parsed, err == nil
		}
	}
	return 0, false
}
