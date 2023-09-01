package scripts

import (
	"embed"
	_ "embed"
	"math/rand"
	"path/filepath"
	"time"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/scripts/buffer"
)

//go:embed js
var embedFS embed.FS

//go:embed exports.js
var exports string

func init() {
	// TODO: Bundle scripts on init and register them on runtime
	rand.Seed(time.Now().UnixNano())
}

func initNative(runtime *goja.Runtime) {
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

// RegisterNativeScripts registers all native scripts in the runtime
func RegisterNativeScripts(runtime *goja.Runtime) error {
	initNative(runtime)

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
		_, err = runtime.RunString(string(contents))
		if err != nil {
			return err
		}
	}
	_, err = runtime.RunString(exports)
	if err != nil {
		return err
	}
	return nil
}
