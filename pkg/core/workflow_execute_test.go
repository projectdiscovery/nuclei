package core

import (
	"context"
	"sync"
	"testing"
	"time"

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

func TestWorkflowsConcurrentExecution(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	numTemplates := 4
	processingTime := 40 * time.Millisecond
	var allExecutionTimes []time.Time
	var timesMutex sync.Mutex
	var executedInputs []string
	var inputsMutex sync.Mutex

	var workflowTemplates []*workflows.WorkflowTemplate
	for range numTemplates {
		template := &workflows.WorkflowTemplate{
			Executers: []*workflows.ProtocolExecuterPair{{
				Executer: &timedMockExecuter{
					result:         true,
					processingTime: processingTime,
					timesMutex:     &timesMutex,
					executeHook: func(input *contextargs.MetaInput) {
						inputsMutex.Lock()
						executedInputs = append(executedInputs, input.Input)
						inputsMutex.Unlock()
					},
				},
				Options: &protocols.ExecutorOptions{Progress: progressBar},
			}},
		}
		workflowTemplates = append(workflowTemplates, template)
	}

	workflow := &workflows.Workflow{
		Options: &protocols.ExecutorOptions{
			Options: &types.Options{TemplateThreads: numTemplates},
		},
		Workflows: workflowTemplates,
	}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)

	startTime := time.Now()
	matched := engine.executeWorkflow(ctx, workflow)
	totalTime := time.Since(startTime)

	// Collect execution times from all executers
	for _, template := range workflowTemplates {
		for _, executer := range template.Executers {
			if timedExec, ok := executer.Executer.(*timedMockExecuter); ok {
				timesMutex.Lock()
				allExecutionTimes = append(allExecutionTimes, timedExec.executionTimes...)
				timesMutex.Unlock()
			}
		}
	}

	t.Logf("Workflow execution completed in: %v", totalTime)
	t.Logf("Templates executed: %d", len(executedInputs))
	t.Logf("Execution times collected: %d", len(allExecutionTimes))

	// test 1: verify workflow execution completed successfully
	require.True(t, matched, "Workflow execution should have matched")

	// test 2: verify all templates were executed
	inputsMutex.Lock()
	require.Equal(t, numTemplates, len(executedInputs), "All templates should have been executed")
	inputsMutex.Unlock()
}

// timedMockExecuter extends mockExecuter with timing capabilities for concurrency testing
type timedMockExecuter struct {
	result         bool
	executeHook    func(input *contextargs.MetaInput)
	outputs        []*output.InternalWrappedEvent
	processingTime time.Duration
	executionTimes []time.Time
	timesMutex     *sync.Mutex
}

func (m *timedMockExecuter) Compile() error { return nil }
func (m *timedMockExecuter) Requests() int  { return 1 }

func (m *timedMockExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	// Track execution start time
	if m.timesMutex != nil {
		m.timesMutex.Lock()
		m.executionTimes = append(m.executionTimes, time.Now())
		m.timesMutex.Unlock()
	}

	if m.executeHook != nil {
		m.executeHook(ctx.Input.MetaInput)
	}

	// Simulate processing time
	if m.processingTime > 0 {
		time.Sleep(m.processingTime)
	}

	return m.result, nil
}

func (m *timedMockExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	_, err := m.Execute(ctx)
	for _, output := range m.outputs {
		ctx.LogEvent(output)
	}
	return ctx.GenerateResult(), err
}

type mockExecuter struct {
	result      bool
	executeHook func(input *contextargs.MetaInput)
	outputs     []*output.InternalWrappedEvent
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
	return m.result, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (m *mockExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	if m.executeHook != nil {
		m.executeHook(ctx.Input.MetaInput)
	}
	for _, output := range m.outputs {
		ctx.LogEvent(output)
	}
	return ctx.GenerateResult(), nil
}
