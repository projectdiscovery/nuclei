package cache

import (
	"regexp"
	"testing"

	"github.com/Knetic/govaluate"
)

func TestRegexCache_SetGet(t *testing.T) {
	// ensure init
	c := Regex()
	pattern := "abc(\n)?123"
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := c.Set(pattern, re); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.GetIFPresent(pattern)
	if err != nil || got == nil {
		t.Fatalf("get: %v got=%v", err, got)
	}
	if got.String() != re.String() {
		t.Fatalf("mismatch: %s != %s", got.String(), re.String())
	}
}

func TestDSLCache_SetGet(t *testing.T) {
	c := DSL()
	expr := "1 + 2 == 3"
	ast, err := govaluate.NewEvaluableExpression(expr)
	if err != nil {
		t.Fatalf("dsl compile: %v", err)
	}
	if err := c.Set(expr, ast); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := c.GetIFPresent(expr)
	if err != nil || got == nil {
		t.Fatalf("get: %v got=%v", err, got)
	}
	if got.String() != ast.String() {
		t.Fatalf("mismatch: %s != %s", got.String(), ast.String())
	}
}

func TestRegexCache_EvictionByCapacity(t *testing.T) {
	SetCapacities(3, 3)
	c := Regex()
	for i := 0; i < 5; i++ {
		k := string(rune('a' + i))
		re := regexp.MustCompile(k)
		_ = c.Set(k, re)
	}
	// last 3 keys expected to remain under LRU: 'c','d','e'
	if _, err := c.GetIFPresent("a"); err == nil {
		t.Fatalf("expected 'a' to be evicted")
	}
	if _, err := c.GetIFPresent("b"); err == nil {
		t.Fatalf("expected 'b' to be evicted")
	}
	if _, err := c.GetIFPresent("c"); err != nil {
		t.Fatalf("expected 'c' present")
	}
}
