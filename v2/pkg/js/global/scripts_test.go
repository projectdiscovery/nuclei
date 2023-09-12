package global

import (
	"testing"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
)

func TestScriptsRuntime(t *testing.T) {
	defaultImports = ""
	runtime := goja.New()

	registry := new(require.Registry)
	registry.Enable(runtime)
	console.Enable(runtime)

	err := RegisterNativeScripts(runtime)
	if err != nil {
		t.Fatal(err)
	}
	value, err := runtime.RunString("dump_json({a: 1, b: 2})")
	if err != nil {
		t.Fatal(err)
	}
	_ = value
}
