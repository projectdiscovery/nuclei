package runner

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

// simulateOnResultCallback reproduces the OnResult callback from lazy.go.
// It silently skips events without operator results and only errors post-execution
// if no data was extracted at all.
func simulateOnResultCallback(templatePath string, events []*output.InternalWrappedEvent) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	for _, e := range events {
		if e == nil {
			continue
		}
		if !e.HasOperatorResult() {
			continue
		}
		for k, v := range e.OperatorsResult.DynamicValues {
			for _, value := range v {
				oldVal, ok := data[k]
				if !ok || len(value) > len(oldVal.(string)) {
					data[k] = value
				}
			}
		}
		for k, v := range e.OperatorsResult.Extracts {
			if len(v) > 0 {
				data[k] = v[0]
			}
		}
	}

	var finalErr error
	if len(data) == 0 {
		finalErr = fmt.Errorf("no extracted values found for template: %s", templatePath)
	}
	return data, finalErr
}

// flowEvents returns a pair of events simulating a flow: http(1) && http(2)
// where http(1) has no matchers and http(2) has extractors.
func flowEvents() []*output.InternalWrappedEvent {
	return []*output.InternalWrappedEvent{
		{InternalEvent: map[string]interface{}{"status_code": 200}},
		{
			OperatorsResult: &operators.Result{
				Matched: true,
				Extracts: map[string][]string{
					"userid":     {"USER-042"},
					"customerid": {"CUST-001"},
				},
			},
			InternalEvent: map[string]interface{}{"status_code": 200},
		},
	}
}

// TestCallbackWorksWithFlowTemplate verifies that the OnResult callback
// correctly handles flow templates (e.g., flow: http(1) && http(2)) where
// the first request has no matchers/extractors and the second has extractors.
// Regression test for #7295.
func TestCallbackWorksWithFlowTemplate(t *testing.T) {
	data, err := simulateOnResultCallback("login.yaml", flowEvents())

	require.Equal(t, "USER-042", data["userid"])
	require.Equal(t, "CUST-001", data["customerid"])
	require.NoError(t, err, "should not error when data is extracted from a later event")
}

// TestCallbackSingleRequest verifies single-request templates still work.
func TestCallbackSingleRequest(t *testing.T) {
	events := []*output.InternalWrappedEvent{
		{
			OperatorsResult: &operators.Result{
				Matched: true,
				Extracts: map[string][]string{
					"token": {"abc123"},
				},
			},
			InternalEvent: map[string]interface{}{},
		},
	}

	data, err := simulateOnResultCallback("auth.yaml", events)

	require.NoError(t, err)
	require.Equal(t, "abc123", data["token"])
}

// TestCallbackNoExtraction verifies error is returned when nothing is extracted.
func TestCallbackNoExtraction(t *testing.T) {
	events := []*output.InternalWrappedEvent{
		{InternalEvent: map[string]interface{}{"status_code": 404}},
	}

	data, err := simulateOnResultCallback("auth.yaml", events)

	require.Error(t, err)
	require.Contains(t, err.Error(), "no extracted values")
	require.Empty(t, data)
}

// TestCallbackNilEvent verifies nil events are safely ignored.
func TestCallbackNilEvent(t *testing.T) {
	events := []*output.InternalWrappedEvent{nil}

	data, err := simulateOnResultCallback("auth.yaml", events)

	require.Error(t, err)
	require.Contains(t, err.Error(), "no extracted values")
	require.Empty(t, data)
}

// TestCallbackDynamicValues verifies dynamic values (internal extractors) are captured.
func TestCallbackDynamicValues(t *testing.T) {
	events := []*output.InternalWrappedEvent{
		{
			OperatorsResult: &operators.Result{
				Matched: true,
				DynamicValues: map[string][]string{
					"session": {"sess-xyz-123", "sess-a"},
				},
			},
			InternalEvent: map[string]interface{}{},
		},
	}

	data, err := simulateOnResultCallback("auth.yaml", events)

	require.NoError(t, err)
	require.Equal(t, "sess-xyz-123", data["session"], "should pick the longest value")
}
