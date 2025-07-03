package js

import (
	"embed"
	"fmt"
	"path/filepath"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
)

//go:embed node_libraries
var nodeLibraries embed.FS

func RegisterNodeModules(runtime *goja.Runtime) {
	registry := require.NewRegistry(
		require.WithGlobalFolders("."),
		require.WithLoader(func(path string) ([]byte, error) {
			path = filepath.Join("node_libraries", path, "index.js")

			data, err := nodeLibraries.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("could not load module %q: %w", path, err)
			}

			return data, nil
		}),
	)

	registry.Enable(runtime)
}
