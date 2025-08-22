package exprcache

import (
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

type ExpressionCache struct {
	cache     map[string]*govaluate.EvaluableExpression
	cacheLock sync.RWMutex
	functions map[string]govaluate.ExpressionFunction
}

func New() *ExpressionCache {
	return &ExpressionCache{
		cache: make(map[string]*govaluate.EvaluableExpression),
	}
}

func NewWithFunctions(functions map[string]govaluate.ExpressionFunction) *ExpressionCache {
	return &ExpressionCache{
		cache:     make(map[string]*govaluate.EvaluableExpression),
		functions: functions,
	}
}

func (ec *ExpressionCache) Get(expression string) (*govaluate.EvaluableExpression, error) {
	ec.cacheLock.RLock()
	if compiled, exists := ec.cache[expression]; exists {
		ec.cacheLock.RUnlock()
		return compiled, nil
	}
	ec.cacheLock.RUnlock()

	var compiled *govaluate.EvaluableExpression
	var err error

	if ec.functions != nil {
		compiled, err = govaluate.NewEvaluableExpressionWithFunctions(expression, ec.functions)
	} else {
		compiled, err = govaluate.NewEvaluableExpression(expression)
	}

	if err != nil {
		return nil, err
	}

	ec.cacheLock.Lock()
	ec.cache[expression] = compiled
	ec.cacheLock.Unlock()

	return compiled, nil
}

func (ec *ExpressionCache) Clear() {
	ec.cacheLock.Lock()
	ec.cache = make(map[string]*govaluate.EvaluableExpression)
	ec.cacheLock.Unlock()
}

func (ec *ExpressionCache) Size() int {
	ec.cacheLock.RLock()
	defer ec.cacheLock.RUnlock()
	return len(ec.cache)
}

var (
	DefaultCache *ExpressionCache
	DSLCache     *ExpressionCache
)

func init() {
	DefaultCache = New()
	DSLCache = NewWithFunctions(dsl.HelperFunctions)
}

func GetCompiledExpression(expression string) (*govaluate.EvaluableExpression, error) {
	return DefaultCache.Get(expression)
}

func GetCompiledDSLExpression(expression string) (*govaluate.EvaluableExpression, error) {
	return DSLCache.Get(expression)
}
