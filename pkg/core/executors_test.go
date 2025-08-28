package core

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// fakeExecuter is a simple stub for protocols.Executer used to test executeTemplateOnInput
type fakeExecuter struct {
	withResults bool
}

func (f *fakeExecuter) Compile() error                              { return nil }
func (f *fakeExecuter) Requests() int                               { return 1 }
func (f *fakeExecuter) Execute(ctx *scan.ScanContext) (bool, error) { return !f.withResults, nil }
func (f *fakeExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	if !f.withResults {
		return nil, nil
	}
	return []*output.ResultEvent{{Host: "h"}}, nil
}

// newTestEngine creates a minimal Engine for tests
func newTestEngine() *Engine {
	return &Engine{options: &types.Options{}}
}

func Test_executeTemplateOnInput_CallbackPath(t *testing.T) {
	e := newTestEngine()
	called := 0
	e.Callback = func(*output.ResultEvent) { called++ }

	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: true}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true")
	}
	if called == 0 {
		t.Fatalf("expected callback to be called")
	}
}

func Test_executeTemplateOnInput_ExecutePath(t *testing.T) {
	e := newTestEngine()
	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: false}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true from Execute path")
	}
}
