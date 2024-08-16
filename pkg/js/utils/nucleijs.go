package utils

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

// temporary on demand runtime to throw errors when vm is not available
var (
	tmpRuntime  *goja.Runtime
	runtimeInit func() = sync.OnceFunc(func() {
		tmpRuntime = goja.New()
	})
)

func getRuntime() *goja.Runtime {
	runtimeInit()
	return tmpRuntime
}

// NucleiJS is js bindings that handles goja runtime related issue
// and allows setting a defer statements to close resources
type NucleiJS struct {
	vm        *goja.Runtime
	ObjectSig string
}

// NewNucleiJS creates a new nucleijs instance
func NewNucleiJS(vm *goja.Runtime) *NucleiJS {
	return &NucleiJS{vm: vm}
}

// internal runtime getter
func (j *NucleiJS) runtime() *goja.Runtime {
	if j == nil {
		return getRuntime()
	}
	return j.vm
}

// see: https://arc.net/l/quote/wpenftpc for throwing docs

// ThrowError throws an error in goja runtime if is not nil
func (j *NucleiJS) ThrowError(err error) {
	if err == nil {
		return
	}
	panic(j.runtime().ToValue(err.Error()))
}

// HandleError handles error and throws a
func (j *NucleiJS) HandleError(err error, msg ...string) {
	if err == nil {
		return
	}
	if len(msg) == 0 {
		j.ThrowError(err)
	}
	j.Throw("%s: %s", strings.Join(msg, ":"), err.Error())
}

// Throw throws an error in goja runtime
func (j *NucleiJS) Throw(format string, args ...interface{}) {
	if len(args) > 0 {
		panic(j.runtime().ToValue(fmt.Sprintf(format, args...)))
	}

	panic(j.runtime().ToValue(format))
}

// GetArg returns argument at index from goja runtime if not found throws error
func (j *NucleiJS) GetArg(args []goja.Value, index int) any {
	if index >= len(args) {
		j.Throw("Missing argument at index %v: %v", index, j.ObjectSig)
	}
	val := args[index]
	if goja.IsUndefined(val) {
		j.Throw("Missing argument at index %v: %v", index, j.ObjectSig)
	}
	return val.Export()
}

// GetArgSafe returns argument at index from goja runtime if not found returns default value
func (j *NucleiJS) GetArgSafe(args []goja.Value, index int, defaultValue any) any {
	if index >= len(args) {
		return defaultValue
	}
	val := args[index]
	if goja.IsUndefined(val) {
		return defaultValue
	}
	return val.Export()
}

// Require throws an error if expression is false
func (j *NucleiJS) Require(expr bool, msg string) {
	if !expr {
		j.Throw("%s", msg)
	}
}

// LinkConstructor links a type with invocation doing this allows
// usage of instance of type in js
func LinkConstructor[T any](call goja.ConstructorCall, vm *goja.Runtime, obj T) *goja.Object {
	instance := vm.ToValue(obj).(*goja.Object)
	_ = instance.SetPrototype(call.This.Prototype())
	return instance
}

// GetStructType gets a type defined in go and passed as argument from goja runtime if not found throws error
// Donot use this unless you are accepting a struct type from constructor
func GetStructType[T any](nj *NucleiJS, args []goja.Value, index int, FuncSig string) T {
	if nj == nil {
		nj = &NucleiJS{}
	}
	if index >= len(args) {
		if FuncSig == "" {
			nj.Throw("Missing argument at index %v", index)
		}
		nj.Throw("Missing arguments expected : %v", FuncSig)
	}
	value := args[index]
	// validate type
	var ptr T
	expected := reflect.ValueOf(ptr).Type()
	argType := expected.Name()
	valueType := value.ExportType().Name()

	if argType != valueType {
		nj.Throw("Type Mismatch expected %v got %v", argType, valueType)
	}

	ptrValue := reflect.New(expected).Elem()
	ptrValue.Set(reflect.ValueOf(value.Export()))

	return ptrValue.Interface().(T)
}

// GetStructTypeSafe gets an type defined in go and passed as argument from goja runtime if not found returns default value
// Donot use this unless you are accepting a struct type from constructor
func GetStructTypeSafe[T any](nj *NucleiJS, args []goja.Value, index int, defaultValue T) T {
	if nj == nil {
		nj = &NucleiJS{}
	}
	if index >= len(args) {
		return defaultValue
	}
	value := args[index]
	// validate type
	var ptr T
	argType := reflect.ValueOf(ptr).Type().Name()
	valueType := value.ExportType().Name()

	if argType != valueType {
		return defaultValue
	}
	return value.ToObject(nj.runtime()).Export().(T)
}
