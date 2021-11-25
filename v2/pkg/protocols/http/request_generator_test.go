package http

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
)

func TestRequestGeneratorPaths(t *testing.T) {
	req := &Request{
		Path: []string{"{{BaseURL}}/test", "{{BaseURL}}/test.php"},
	}
	generator := req.newGenerator()
	var payloads []string
	for {
		raw, _, ok := generator.nextValue()
		if !ok {
			break
		}
		payloads = append(payloads, raw)
	}
	require.Equal(t, req.Path, payloads, "Could not get correct paths")
}

func TestRequestGeneratorClusterBombSingle(t *testing.T) {
	var err error

	req := &Request{
		Payloads:   map[string]interface{}{"username": []string{"admin", "tomcat", "manager"}, "password": []string{"password", "test", "secret"}},
		AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
		Raw:        []string{`GET /{{username}}:{{password}} HTTP/1.1`},
	}
	catalogInstance := catalog.New("")
	req.generator, err = generators.New(req.Payloads, req.AttackType.Value, "", catalogInstance)
	require.Nil(t, err, "could not create generator")

	generator := req.newGenerator()
	var payloads []map[string]interface{}
	for {
		_, data, ok := generator.nextValue()
		if !ok {
			break
		}
		payloads = append(payloads, data)
	}
	require.Equal(t, 9, len(payloads), "Could not get correct number of payloads")
}

func TestRequestGeneratorClusterBombMultipleRaw(t *testing.T) {
	var err error

	req := &Request{
		Payloads:   map[string]interface{}{"username": []string{"admin", "tomcat", "manager"}, "password": []string{"password", "test", "secret"}},
		AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
		Raw:        []string{`GET /{{username}}:{{password}} HTTP/1.1`, `GET /{{username}}@{{password}} HTTP/1.1`},
	}
	catalogInstance := catalog.New("")
	req.generator, err = generators.New(req.Payloads, req.AttackType.Value, "", catalogInstance)
	require.Nil(t, err, "could not create generator")

	generator := req.newGenerator()
	var payloads []map[string]interface{}
	for {
		_, data, ok := generator.nextValue()
		if !ok {
			break
		}
		payloads = append(payloads, data)
	}
	require.Equal(t, 18, len(payloads), "Could not get correct number of payloads")
}
