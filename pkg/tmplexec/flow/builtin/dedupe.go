package builtin

import (
	"crypto/md5"
	"reflect"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Dedupe is a javascript builtin for deduping values
type Dedupe struct {
	m  map[string]goja.Value
	VM *goja.Runtime
}

// Add adds a value to the dedupe
func (d *Dedupe) Add(call goja.FunctionCall) goja.Value {
	allVars := []any{}
	for _, v := range call.Arguments {
		if v.Export() == nil {
			continue
		}
		if v.ExportType().Kind() == reflect.Slice {
			// convert []datatype to []interface{}
			// since it cannot be type asserted to []interface{} directly
			rfValue := reflect.ValueOf(v.Export())
			for i := 0; i < rfValue.Len(); i++ {
				allVars = append(allVars, rfValue.Index(i).Interface())
			}
		} else {
			allVars = append(allVars, v.Export())
		}
	}
	for _, v := range allVars {
		hash := hashValue(v)
		if _, ok := d.m[hash]; ok {
			continue
		}
		d.m[hash] = d.VM.ToValue(v)
	}
	return d.VM.ToValue(true)
}

// Values returns all values from the dedupe
func (d *Dedupe) Values(call goja.FunctionCall) goja.Value {
	tmp := []goja.Value{}
	for _, v := range d.m {
		tmp = append(tmp, v)
	}
	return d.VM.ToValue(tmp)
}

// NewDedupe creates a new dedupe builtin object
func NewDedupe(vm *goja.Runtime) *Dedupe {
	return &Dedupe{
		m:  make(map[string]goja.Value),
		VM: vm,
	}
}

// hashValue returns a hash of the value
func hashValue(value interface{}) string {
	res := types.ToString(value)
	md5sum := md5.Sum([]byte(res))
	return string(md5sum[:])
}
