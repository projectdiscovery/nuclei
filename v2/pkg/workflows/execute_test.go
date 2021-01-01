package workflows

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/stretchr/testify/require"
)

func TestWorkflowsSimple(t *testing.T) {
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: true}},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
	require.True(t, matched, "could not get correct match value")
}

func TestWorkflowsSimpleMultiple(t *testing.T) {
	var firstInput, secondInput string
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: true, executeHook: func(input string) {
			firstInput = input
		}}},
		{Executer: &mockExecuter{result: true, executeHook: func(input string) {
			secondInput = input
		}}},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplates(t *testing.T) {
	var firstInput, secondInput string
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: true, executeHook: func(input string) {
			firstInput = input
		}},
			Subtemplates: []*WorkflowTemplate{
				{Executer: &mockExecuter{result: true, executeHook: func(input string) {
					secondInput = input
				}}},
			}},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesNoMatch(t *testing.T) {
	var firstInput, secondInput string
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: false, executeHook: func(input string) {
			firstInput = input
		}},
			Subtemplates: []*WorkflowTemplate{
				{Executer: &mockExecuter{result: true, executeHook: func(input string) {
					secondInput = input
				}}},
			}},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
	require.False(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcher(t *testing.T) {
	var firstInput, secondInput string
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: true, executeHook: func(input string) {
			firstInput = input
		}, outputs: []*output.InternalWrappedEvent{
			{OperatorsResult: &operators.Result{
				Matches:  map[string]struct{}{"tomcat": {}},
				Extracts: map[string][]string{},
			}},
		}},
			Matchers: []*Matcher{
				{Name: "tomcat", Subtemplates: []*WorkflowTemplate{
					{Executer: &mockExecuter{result: true, executeHook: func(input string) {
						secondInput = input
					}}},
				}},
			},
		},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
	require.True(t, matched, "could not get correct match value")

	require.Equal(t, "https://test.com", firstInput, "could not get correct first input")
	require.Equal(t, "https://test.com", secondInput, "could not get correct second input")
}

func TestWorkflowsSubtemplatesWithMatcherNoMatch(t *testing.T) {
	var firstInput, secondInput string
	workflow := &Workflow{Workflows: []*WorkflowTemplate{
		{Executer: &mockExecuter{result: true, executeHook: func(input string) {
			firstInput = input
		}, outputs: []*output.InternalWrappedEvent{
			{OperatorsResult: &operators.Result{
				Matches:  map[string]struct{}{"tomcat": {}},
				Extracts: map[string][]string{},
			}},
		}},
			Matchers: []*Matcher{
				{Name: "apache", Subtemplates: []*WorkflowTemplate{
					{Executer: &mockExecuter{result: true, executeHook: func(input string) {
						secondInput = input
					}}},
				}},
			},
		},
	}}

	matched, err := workflow.RunWorkflow("https://test.com")
	require.Nil(t, err, "could not run workflow")
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
