package expressions

import (
	"strings"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/cache"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

// badExprCacheCap caps the negative-result cache (expressions that fail to compile).
// Keeping it small bounds memory while still preventing repeated parse work for
// pathological input that appears repeatedly in the same scan.
const badExprCacheCap = 2048

// bareExprCacheCap caps the cache for govaluate.NewEvaluableExpression (no helper functions).
// This is hit from isExpression which discriminates whether a {{...}} substring is a valid
// govaluate expression. Hot in DSL-heavy templates.
const bareExprCacheCap = 4096

var (
	badExprOnce  sync.Once
	badExprCache gcache.Cache[string, struct{}]

	bareExprOnce  sync.Once
	bareExprCache gcache.Cache[string, *govaluate.EvaluableExpression]
)

func badExpr() gcache.Cache[string, struct{}] {
	badExprOnce.Do(func() {
		badExprCache = gcache.New[string, struct{}](badExprCacheCap).LRU().Build()
	})
	return badExprCache
}

func bareExpr() gcache.Cache[string, *govaluate.EvaluableExpression] {
	bareExprOnce.Do(func() {
		bareExprCache = gcache.New[string, *govaluate.EvaluableExpression](bareExprCacheCap).LRU().Build()
	})
	return bareExprCache
}

// compileExprWithFunctions compiles a govaluate expression with the DSL helper
// function table, caching both successes (in the shared dsl cache) and
// failures (in a small local negative cache). Callers in this package should
// use this helper instead of calling govaluate.NewEvaluableExpressionWithFunctions
// directly so per-request hot paths do not pay parse cost on every invocation.
func compileExprWithFunctions(src string) (*govaluate.EvaluableExpression, error) {
	c := cache.DSL()
	if compiled, err := c.GetIFPresent(src); err == nil && compiled != nil {
		return compiled, nil
	}
	if _, err := badExpr().GetIFPresent(src); err == nil {
		// Known-bad: re-run the parser to surface the original error message.
		// This is rare; the cache prevents the common case of repeated parse work.
		return govaluate.NewEvaluableExpressionWithFunctions(src, dsl.HelperFunctions)
	}
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(src, dsl.HelperFunctions)
	if err != nil {
		_ = badExpr().Set(src, struct{}{})
		return nil, err
	}
	_ = c.Set(src, compiled)
	return compiled, nil
}

// compileBareExpr compiles a govaluate expression without DSL helpers, used by
// isExpression to discriminate between bare expressions and helper-function
// invocations. Cached separately because it has different parse semantics
// from the with-functions variant (functions are unknown identifiers).
func compileBareExpr(src string) (*govaluate.EvaluableExpression, error) {
	c := bareExpr()
	if compiled, err := c.GetIFPresent(src); err == nil && compiled != nil {
		return compiled, nil
	}
	compiled, err := govaluate.NewEvaluableExpression(src)
	if err != nil {
		return nil, err
	}
	_ = c.Set(src, compiled)
	return compiled, nil
}

// baseHasAnyKey reports whether any key in base appears as a substring in
// data. Replaces an O(len(base)) []string allocation that getFunctionsNames
// previously incurred on every isExpression call.
func baseHasAnyKey(data string, base map[string]interface{}) bool {
	for k := range base {
		if k == "" {
			continue
		}
		if strings.Contains(data, k) {
			return true
		}
	}
	return false
}
