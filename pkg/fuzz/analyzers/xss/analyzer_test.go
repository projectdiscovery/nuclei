package xss

import "testing"

func TestName(t *testing.T) {
    a := &Analyzer{}
    if got := a.Name(); got != "xss_context" {
        t.Errorf("Analyzer.Name() = %q; want \"xss_context\"", got)
    }
}