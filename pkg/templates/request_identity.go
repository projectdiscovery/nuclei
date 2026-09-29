package templates

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
)

const requestBlockIdentityVersion = "v1"

func normalizeRequestIdentityPreprocessors(data []byte, replacements map[string]interface{}) []byte {
	expressions := make([]string, 0, len(replacements))
	for expression := range replacements {
		expressions = append(expressions, expression)
	}
	sort.Slice(expressions, func(i, j int) bool {
		if len(expressions[i]) != len(expressions[j]) {
			return len(expressions[i]) > len(expressions[j])
		}
		return expressions[i] < expressions[j]
	})

	normalized := data
	for _, expression := range expressions {
		digest := sha256.Sum256([]byte(expression))
		sentinel := fmt.Sprintf("nuclei_request_identity_%x", digest[:8])
		normalized = bytes.ReplaceAll(normalized, []byte(expression), []byte(sentinel))
	}
	return normalized
}

func (template *Template) assignRequestBlockIDs() error {
	return template.assignRequestBlockIDsFrom(template)
}

func (template *Template) assignRequestBlockIDsFrom(source *Template) error {
	if err := assignRequestBlockIDsFor(template.RequestsDNS, source.RequestsDNS); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsFile, source.RequestsFile); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsNetwork, source.RequestsNetwork); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsHTTP, source.RequestsHTTP); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsHeadless, source.RequestsHeadless); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsSSL, source.RequestsSSL); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsWebsocket, source.RequestsWebsocket); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsWHOIS, source.RequestsWHOIS); err != nil {
		return err
	}
	if err := assignRequestBlockIDsFor(template.RequestsCode, source.RequestsCode); err != nil {
		return err
	}
	return assignRequestBlockIDsFor(template.RequestsJavascript, source.RequestsJavascript)
}

type requestBlockIdentifiable interface {
	protocols.Request
	SetRequestBlockID(string)
}

func assignRequestBlockIDsFor[T requestBlockIdentifiable](targets, sources []T) error {
	if len(targets) != len(sources) {
		return errors.New("request identity source does not match parsed template")
	}
	var explicitIDs map[string]struct{}
	for index, source := range sources {
		if id := source.GetID(); id != "" {
			if _, exists := explicitIDs[id]; exists {
				return errors.Errorf("duplicate explicit %s request id %q", source.Type(), id)
			}
			if explicitIDs == nil {
				explicitIDs = make(map[string]struct{}, len(sources))
			}
			explicitIDs[id] = struct{}{}
		}
		identity, err := requestBlockID(source)
		if err != nil {
			return errors.Wrapf(err, "could not calculate %s request block identity", source.Type())
		}
		targets[index].SetRequestBlockID(identity)
	}
	return nil
}

func requestBlockID(request protocols.Request) (string, error) {
	protocol := request.Type().String()
	if id := request.GetID(); id != "" {
		return fmt.Sprintf("%s:%s:explicit:%s", requestBlockIdentityVersion, protocol, id), nil
	}

	definition, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(definition)
	return fmt.Sprintf("%s:%s:sha256:%x", requestBlockIdentityVersion, protocol, digest), nil
}

func (template *Template) protocolRequestGroups() [][]protocols.Request {
	return [][]protocols.Request{
		template.convertRequestToProtocolsRequest(template.RequestsDNS),
		template.convertRequestToProtocolsRequest(template.RequestsFile),
		template.convertRequestToProtocolsRequest(template.RequestsNetwork),
		template.convertRequestToProtocolsRequest(template.RequestsHTTP),
		template.convertRequestToProtocolsRequest(template.RequestsHeadless),
		template.convertRequestToProtocolsRequest(template.RequestsSSL),
		template.convertRequestToProtocolsRequest(template.RequestsWebsocket),
		template.convertRequestToProtocolsRequest(template.RequestsWHOIS),
		template.convertRequestToProtocolsRequest(template.RequestsCode),
		template.convertRequestToProtocolsRequest(template.RequestsJavascript),
	}
}
