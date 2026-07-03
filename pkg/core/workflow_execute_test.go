package core

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	"github.com/stretchr/testify/require"
)

func TestWorkflowsSimple(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")
}

func TestWorkflowsSimpleMultiple(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				firstInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}},
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				secondInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplates(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				firstInput = input.Input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{}, Results: []*output.ResultEvent{{}}},
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				secondInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}}}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesNoMatch(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: false, executeHook: func(input *contextargs.MetaInput) {
				firstInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				secondInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}}}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.False(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcher(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				firstInput = input.Input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{
					Matches:  map[string][]string{"tomcat": {}},
					Extracts: map[string][]string{},
				}},
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}, Matchers: []*workflows.Matcher{{Name: stringslice.StringSlice{Value: "tomcat"}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				secondInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}}}}}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcherNoMatch(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				firstInput = input.Input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{
					Matches:  map[string][]string{"tomcat": {}},
					Extracts: map[string][]string{},
				}},
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}, Matchers: []*workflows.Matcher{{Name: stringslice.StringSlice{Value: "apache"}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input *contextargs.MetaInput) {
				secondInput = input.Input
			}}, Options: &protocols.ExecutorOptions{Progress: progressBar}},
		}}}}}},
	}}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.False(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesPropagateParentContextToChildTemplateCtx(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	childOptions := &protocols.ExecutorOptions{TemplateID: "child-template", Progress: progressBar}
	var childWhoami interface{}

	workflow := &workflows.Workflow{
		Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}},
		Workflows: []*workflows.WorkflowTemplate{{
			Executers: []*workflows.ProtocolExecuterPair{{
				Executer: &mockExecuter{result: true, outputs: []*output.InternalWrappedEvent{{
					OperatorsResult: &operators.Result{Extracts: map[string][]string{"whoami": {"foo"}}},
					Results:         []*output.ResultEvent{{}},
				}}},
				Options: &protocols.ExecutorOptions{TemplateID: "parent-template", Progress: progressBar},
			}},
			Subtemplates: []*workflows.WorkflowTemplate{{
				Executers: []*workflows.ProtocolExecuterPair{{
					Executer: &mockExecuter{result: true, executeScanHook: func(ctx *scan.ScanContext) {
						childWhoami, _ = childOptions.GetTemplateCtx(ctx.Input.MetaInput).Get("whoami")
					}},
					Options: childOptions,
				}},
			}},
		}},
	}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "foo", childWhoami, "could not inherit workflow context into child template context")
}

func TestWorkflowsSubtemplatesDoNotShareSiblingContext(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	firstSiblingReady := make(chan struct{})
	var secondSiblingHasSiblingValue bool

	workflow := &workflows.Workflow{
		Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}},
		Workflows: []*workflows.WorkflowTemplate{{
			Executers: []*workflows.ProtocolExecuterPair{{
				Executer: &mockExecuter{result: true, outputs: []*output.InternalWrappedEvent{{
					OperatorsResult: &operators.Result{},
					Results:         []*output.ResultEvent{{}},
				}}},
				Options: &protocols.ExecutorOptions{TemplateID: "parent-template", Progress: progressBar},
			}},
			Subtemplates: []*workflows.WorkflowTemplate{
				{
					Executers: []*workflows.ProtocolExecuterPair{{
						Executer: &mockExecuter{result: true, executeScanHook: func(ctx *scan.ScanContext) {
							ctx.Input.Set("sibling-only", "from-first-sibling")
							close(firstSiblingReady)
						}},
						Options: &protocols.ExecutorOptions{TemplateID: "first-child-template", Progress: progressBar},
					}},
				},
				{
					Executers: []*workflows.ProtocolExecuterPair{{
						Executer: &mockExecuter{result: true, executeScanHook: func(ctx *scan.ScanContext) {
							<-firstSiblingReady
							_, secondSiblingHasSiblingValue = ctx.Input.Get("sibling-only")
						}},
						Options: &protocols.ExecutorOptions{TemplateID: "second-child-template", Progress: progressBar},
					}},
				},
			},
		}},
	}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.False(t, secondSiblingHasSiblingValue, "sibling subtemplate inherited workflow context from another sibling")
}

func TestWorkflowsSameStepExecutersRefreshTemplateContext(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	secondOptions := &protocols.ExecutorOptions{TemplateID: "second-template", Progress: progressBar}
	var secondWhoami interface{}

	workflow := &workflows.Workflow{
		Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}},
		Workflows: []*workflows.WorkflowTemplate{{
			Executers: []*workflows.ProtocolExecuterPair{
				{
					Executer: &mockExecuter{result: true, outputs: []*output.InternalWrappedEvent{{
						OperatorsResult: &operators.Result{Extracts: map[string][]string{"whoami": {"foo"}}},
						Results:         []*output.ResultEvent{{}},
					}}},
					Options: &protocols.ExecutorOptions{TemplateID: "first-template", Progress: progressBar},
				},
				{
					Executer: &mockExecuter{result: true, executeScanHook: func(ctx *scan.ScanContext) {
						secondWhoami, _ = secondOptions.GetTemplateCtx(ctx.Input.MetaInput).Get("whoami")
					}},
					Options: secondOptions,
				},
			},
			Subtemplates: []*workflows.WorkflowTemplate{{
				Executers: []*workflows.ProtocolExecuterPair{{
					Executer: &mockExecuter{result: true},
					Options:  &protocols.ExecutorOptions{TemplateID: "child-template", Progress: progressBar},
				}},
			}},
		}},
	}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	matched := engine.executeWorkflow(ctx, workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "foo", secondWhoami, "could not refresh workflow context into later executers in the same step")
}

type mockExecuter struct {
	result          bool
	executeHook     func(input *contextargs.MetaInput)
	executeScanHook func(ctx *scan.ScanContext)
	outputs         []*output.InternalWrappedEvent
}

// Compile compiles the execution generators preparing any requests possible.
func (m *mockExecuter) Compile() error {
	return nil
}

// Requests returns the total number of requests the rule will perform
func (m *mockExecuter) Requests() int {
	return 1
}

// Execute executes the protocol group and  returns true or false if results were found.
func (m *mockExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	if m.executeHook != nil {
		m.executeHook(ctx.Input.MetaInput)
	}
	if m.executeScanHook != nil {
		m.executeScanHook(ctx)
	}
	return m.result, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (m *mockExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	if m.executeHook != nil {
		m.executeHook(ctx.Input.MetaInput)
	}
	if m.executeScanHook != nil {
		m.executeScanHook(ctx)
	}
	for _, output := range m.outputs {
		ctx.LogEvent(output)
	}
	return ctx.GenerateResult(), nil
}
