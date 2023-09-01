package scripts

import (
	"embed"
	"math/rand"
	"path/filepath"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/scripts/gotypes/buffer"
)

var (
	//go:embed js
	embedFS embed.FS

	//go:embed exports.js
	exports string
)

// initBuiltInFunc initializes runtime with builtin functions
func initBuiltInFunc(runtime *goja.Runtime) {
	module := buffer.Module{}
	module.Enable(runtime)

	runtime.Set("Rand", func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rand.Intn(255))
		}
		return b
	})
	runtime.Set("RandInt", func() int64 {
		return rand.Int63()
	})
}

// RegisterNativeScripts are js scripts that were added for convenience
// and abstraction purposes we execute them in every runtime and make them
// available for use in any js script
// see: scripts/ for examples
func RegisterNativeScripts(runtime *goja.Runtime) error {
	initBuiltInFunc(runtime)

	dirs, err := embedFS.ReadDir("js")
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if dir.IsDir() {
			continue
		}
		contents, err := embedFS.ReadFile(filepath.Join("js", dir.Name()))
		if err != nil {
			return err
		}
		// run all built in js helper functions or scripts
		_, err = runtime.RunString(string(contents))
		if err != nil {
			return err
		}
	}
	// exports defines the exports object
	_, err = runtime.RunString(exports)
	if err != nil {
		return err
	}
	return nil
}
