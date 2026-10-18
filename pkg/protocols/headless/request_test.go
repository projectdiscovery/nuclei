package headless

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestRequestsIncludesPayloadExecutions(t *testing.T) {
	payloads := map[string]interface{}{
		"username": []string{"admin", "root"},
		"password": []string{"password", "toor", "guest"},
	}
	generator, err := generators.New(payloads, generators.ClusterBombAttack, "", nil, "", types.DefaultOptions())
	require.NoError(t, err)

	request := &Request{
		AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
		Payloads:   payloads,
		generator:  generator,
	}
	require.Equal(t, 6, request.Requests())
}

func TestHeadlessThreadsRejectUnsafeConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		options protocols.ExecutorOptions
		want    string
	}{
		{name: "above cap", request: Request{Threads: 3}, want: "between 0 and 2"},
		{name: "without payloads", request: Request{Threads: 2, DisableCookie: true}, want: "require payloads"},
		{name: "shared cookies", request: Request{Threads: 2, Payloads: map[string]interface{}{"probe": []string{"one", "two"}}}, want: "isolated cookies"},
		{name: "flow", request: Request{Threads: 2, DisableCookie: true, Payloads: map[string]interface{}{"probe": []string{"one", "two"}}}, options: protocols.ExecutorOptions{Flow: "probe"}, want: "standalone templates"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.options.Options = types.DefaultOptions()
			err := test.request.Compile(&test.options)
			require.ErrorContains(t, err, test.want)
		})
	}
}
