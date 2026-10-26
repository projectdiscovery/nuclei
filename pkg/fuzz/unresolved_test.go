package fuzz

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

type unresolvedProgress struct {
	progress.Progress
	skipped atomic.Int64
}

func (p *unresolvedProgress) IncrementSkippedUnresolved(count int64) { p.skipped.Add(count) }
func (p *unresolvedProgress) SkippedUnresolved() uint64              { return uint64(p.skipped.Load()) }

func TestUnresolvedRuleVariablesAreSkipped(t *testing.T) {
	tests := map[string]*Rule{
		"keys":          {Part: "query", Keys: []string{`{{to_lower("{{nosuchkey}}")}}`}},
		"keys-regex":    {Part: "query", KeysRegex: []string{`{{to_lower("{{nosuchkey}}")}}`}},
		"values-regex":  {Part: "query", ValuesRegex: []string{`{{to_lower("{{nosuchkey}}")}}`}},
		"replace-regex": {Part: "query", Type: "replace-regex", ReplaceRegex: `{{to_lower("{{nosuchkey}}")}}`},
	}
	for name, rule := range tests {
		t.Run(name, func(t *testing.T) {
			prog := &unresolvedProgress{}
			executorOpts := &protocols.ExecutorOptions{
				TemplateID: "unresolved-fuzz",
				Variables:  variables.Variable{InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0)},
				Constants:  map[string]interface{}{},
				Options:    &types.Options{},
				Progress:   prog,
			}
			// the template still loads
			require.NoError(t, rule.Compile(nil, executorOpts))

			input := &ExecuteRuleInput{Input: contextargs.NewWithInput(context.Background(), "http://127.0.0.1/?a=1")}
			require.NoError(t, rule.Execute(input))
			require.NoError(t, rule.Execute(input))
			require.Equal(t, uint64(2), prog.SkippedUnresolved())
		})
	}
}
