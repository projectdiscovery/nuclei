package xss

import (
	"strings"
	"testing"
)

func TestApplyInitialTransformation(t *testing.T) {
	a := &Analyzer{}
	input := "hello[XSS_CANARY]world"
	out := a.ApplyInitialTransformation(input)
	if !strings.Contains(out, a.canary) {
		t.Fatalf("expected canary injected, got %s", out)
	}
	if strings.Contains(out, "[XSS_CANARY]") {
		t.Fatalf("placeholder not replaced")
	}
}