package redis

import (
	lib_redis "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/redis"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/redis")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Connect":            lib_redis.Connect, //nolint:staticcheck // SA1019: retained for JS API compatibility
			"ConnectWithOptions": lib_redis.ConnectWithOptions,
			"GetServerInfo":      lib_redis.GetServerInfo,
			"GetServerInfoAuth":  lib_redis.GetServerInfoAuth,
			"IsAuthenticated":    lib_redis.IsAuthenticated,
			"RunLuaScript":       lib_redis.RunLuaScript,

			// Var and consts

			// Objects / Classes
			"RedisOptions": gojs.GetClassConstructor[lib_redis.RedisOptions](&lib_redis.RedisOptions{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
