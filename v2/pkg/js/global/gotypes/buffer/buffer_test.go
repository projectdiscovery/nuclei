package buffer

import (
	"testing"

	"github.com/dop251/goja"
)

func TestBuffers(t *testing.T) {
	runtime := goja.New()
	module := &Module{}
	module.Enable(runtime)

	_, err := runtime.RunString(`var buffer = bytes.Buffer();`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runtime.RunString(`buffer.append([1, 2, 3]);`)
	if err != nil {
		t.Fatal(err)
	}
	rut, err := runtime.RunString(`buffer.bytes();`)
	if err != nil {
		t.Fatal(err)
	}
	if rut.String() != "1,2,3" {
		t.Fatalf("invalid buffer bytes: %+v", rut.Export().([]uint8))
	}
}
