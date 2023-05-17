package redis

import (
	original_redis "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/redis"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libredis")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"GetServerInfo":   original_redis.GetServerInfo,
			"IsAuthenticated": original_redis.IsAuthenticated,

			// Var and consts

			// Types (value type)
			"Info": func() original_redis.Info { return original_redis.Info{} },

			// Types (pointer type)
			"NewInfo": func() *original_redis.Info { return &original_redis.Info{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
