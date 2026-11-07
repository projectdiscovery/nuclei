package headless

import (
	"testing"

	"github.com/stretchr/testify/require"

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
