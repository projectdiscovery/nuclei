package http

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/stretchr/testify/require"
)

func TestRequestGeneratorClusterSingle(t *testing.T) {
	var err error

	req := &Request{
		Payloads:   map[string]interface{}{"username": []string{"admin", "tomcat", "manager"}, "password": []string{"password", "test", "secret"}},
		attackType: generators.ClusterBomb,
		Raw:        []string{`GET /{{username}}:{{password}} HTTP/1.1`},
	}
	req.generator, err = generators.New(req.Payloads, req.attackType)
	require.Nil(t, err, "could not create generator")

	generator := req.newGenerator()
	var payloads []map[string]interface{}
	for {
		raw, data, ok := generator.nextValue()
		if !ok {
			break
		}
		payloads = append(payloads, data)
		fmt.Printf("%v %v\n", raw, data)
	}
	require.Equal(t, 9, len(payloads), "Could not get correct number of payloads")
}

func TestRequestGeneratorClusterMultipleRaw(t *testing.T) {
	var err error

	req := &Request{
		Payloads:   map[string]interface{}{"username": []string{"admin", "tomcat", "manager"}, "password": []string{"password", "test", "secret"}},
		attackType: generators.ClusterBomb,
		Raw:        []string{`GET /{{username}}:{{password}} HTTP/1.1`, `GET /{{username}}@{{password}} HTTP/1.1`},
	}
	req.generator, err = generators.New(req.Payloads, req.attackType)
	require.Nil(t, err, "could not create generator")

	generator := req.newGenerator()
	var payloads []map[string]interface{}
	for {
		raw, data, ok := generator.nextValue()
		if !ok {
			break
		}
		payloads = append(payloads, data)
		fmt.Printf("%v %v\n", raw, data)
	}
	require.Equal(t, 18, len(payloads), "Could not get correct number of payloads")
}
