package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

func TestWorkflowsSimple(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.True(t, matched, "could not get correct match value")
}

func TestWorkflowsSimpleMultiple(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				firstInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}},
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				secondInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplates(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				firstInput = input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{}, Results: []*output.ResultEvent{{}}},
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				secondInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}}}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesNoMatch(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: false, executeHook: func(input string) {
				firstInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}, Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				secondInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}}}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.False(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcher(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				firstInput = input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{
					Matches:  map[string][]string{"tomcat": {}},
					Extracts: map[string][]string{},
				}},
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}, Matchers: []*workflows.Matcher{{Name: "tomcat", Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				secondInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}}}}}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcherNoMatch(t *testing.T) {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)

	var firstInput, secondInput string
	workflow := &workflows.Workflow{Options: &protocols.ExecuterOptions{Options: &types.Options{TemplateThreads: 10}}, Workflows: []*workflows.WorkflowTemplate{
		{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				firstInput = input
			}, outputs: []*output.InternalWrappedEvent{
				{OperatorsResult: &operators.Result{
					Matches:  map[string][]string{"tomcat": {}},
					Extracts: map[string][]string{},
				}},
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}, Matchers: []*workflows.Matcher{{Name: "apache", Subtemplates: []*workflows.WorkflowTemplate{{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{result: true, executeHook: func(input string) {
				secondInput = input
			}}, Options: &protocols.ExecuterOptions{Progress: progressBar}},
		}}}}}},
	}}

	engine := &Engine{}
	matched := engine.executeWorkflow("https://test.com", workflow)
	require.False(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "", secondInput, "could not get correct second input")
}

type mockExecuter struct {
	result      bool
	executeHook func(input string)
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
func (m *mockExecuter) Execute(input string) (bool, error) {
	if m.executeHook != nil {
		m.executeHook(input)
	}
	return m.result, nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (m *mockExecuter) ExecuteWithResults(input string, callback protocols.OutputEventCallback) error {
	if m.executeHook != nil {
		m.executeHook(input)
	}
	for _, output := range m.outputs {
		callback(output)
	}
	return nil
}
