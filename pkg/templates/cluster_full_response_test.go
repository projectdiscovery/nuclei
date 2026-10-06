package templates

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

func TestClusterMarksFullResponseOnlyWhenNeeded(t *testing.T) {
	bodyOnly := &http.Request{}
	executer := &ClusterExecuter{
		requests: bodyOnly,
		operators: []*clusteredOperator{
			{operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "body"}}}},
			{operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "all"}}}},
		},
	}
	executer.markClusteredResponse()
	require.False(t, bodyOnly.FullResponseRequired())

	withResponse := &http.Request{}
	executer.requests = withResponse
	executer.operators = append(executer.operators, &clusteredOperator{
		operator: &operators.Operators{Matchers: []*matchers.Matcher{{Part: "response"}}},
	})
	executer.markClusteredResponse()
	require.True(t, withResponse.FullResponseRequired())
}
