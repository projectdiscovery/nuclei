package fuzz

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
)

func TestEvaluateVarsWithInteractsh_RaceCondition(t *testing.T) {
	rule := &Rule{}
	rule.options = &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}

	sharedData := map[string]interface{}{
		"var1": "value1",
		"var2": "{{var1}}_suffix",
		"var3": "prefix_{{var1}}",
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rule.evaluateVarsWithInteractsh(sharedData, nil)
		}()
	}
	wg.Wait()
}
