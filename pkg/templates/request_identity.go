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

var requestIdentityIgnoredFields = map[string]struct{}{
	"analyzer":                         {},
	"attack":                           {},
	"cookie-reuse":                     {},
	"custom_user_agent":                {},
	"disable-cookie":                   {},
	"disable-http-cache":               {},
	"digest-password":                  {},
	"digest-username":                  {},
	"exclude-ports":                    {},
	"fuzzing":                          {},
	"host-redirects":                   {},
	"iterate-all":                      {},
	"matchers-condition":               {},
	"max-redirects":                    {},
	"max-size":                         {},
	"no-recursive":                     {},
	"pipeline":                         {},
	"pipeline-concurrent-connections":  {},
	"pipeline-requests-per-connection": {},
	"pre-condition":                    {},
	"pre-condition-operator":           {},
	"protocol-redirects":               {},
	"race":                             {},
	"race_count":                       {},
	"read-all":                         {},
	"read-size":                        {},
	"redirects":                        {},
	"req-condition":                    {},
	"resolvers":                        {},
	"retries":                          {},
	"scan_mode":                        {},
	"skip-secret-file":                 {},
	"skip-variables-check":             {},
	"smb-domain":                       {},
	"smb-hash":                         {},
	"smb-password":                     {},
	"smb-user":                         {},
	"stop-at-first-match":              {},
	"threads":                          {},
	"trace-max-recursion":              {},
	"unsafe":                           {},
	"user_agent":                       {},
}

type requestIdentityOperatorRole struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
}

type requestIdentityOperatorRoles struct {
	External bool                          `json:"external,omitempty"`
	Internal bool                          `json:"internal,omitempty"`
	Named    []requestIdentityOperatorRole `json:"named,omitempty"`
}

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
	SetRequestProbeIDs([]string)
}

func assignRequestBlockIDsFor[T requestBlockIdentifiable](targets, sources []T) error {
	if len(targets) != len(sources) {
		return errors.New("request identity source does not match parsed template")
	}
	var explicitIDCounts map[string]int
	for _, source := range sources {
		if id := source.GetID(); id != "" {
			if explicitIDCounts == nil {
				explicitIDCounts = make(map[string]int, len(sources))
			}
			explicitIDCounts[id]++
		}
	}
	identities := make([]string, len(sources))
	definitions := make([]*requestIdentityDefinitions, len(sources))
	unnamedIdentityCounts := make(map[string]int, len(sources))
	for index, source := range sources {
		definition, err := newRequestIdentityDefinitions(source)
		if err != nil {
			return errors.Wrapf(err, "could not calculate %s request block identity", source.Type())
		}
		if source.GetID() == "" {
			definitions[index] = definition
		}

		useFullDefinition := explicitIDCounts[source.GetID()] > 1
		identity, err := requestBlockIDFromDefinitions(source, definition, useFullDefinition)
		if err != nil {
			return errors.Wrapf(err, "could not calculate %s request block identity", source.Type())
		}
		probeDefinition := definition.projected
		if useFullDefinition {
			probeDefinition = definition.full
		}
		probeIDs, err := requestProbeIDsFromDefinition(source, probeDefinition)
		if err != nil {
			return errors.Wrapf(err, "could not calculate %s request probe identities", source.Type())
		}
		targets[index].SetRequestProbeIDs(probeIDs)
		if source.GetID() == "" {
			unnamedIdentityCounts[identity]++
		}
		identities[index] = identity
	}
	for index, source := range sources {
		identity := identities[index]
		if source.GetID() == "" && unnamedIdentityCounts[identity] > 1 {
			identity = fullStructuralRequestBlockIDFromDefinitions(source, definitions[index])
			probeIDs, err := requestProbeIDsFromDefinition(source, definitions[index].full)
			if err != nil {
				return errors.Wrapf(err, "could not disambiguate %s request probe identities", source.Type())
			}
			targets[index].SetRequestProbeIDs(probeIDs)
		}
		targets[index].SetRequestBlockID(identity)
	}
	return nil
}

type requestIdentityDefinitions struct {
	fullEncoded []byte
	full        map[string]interface{}
	projected   map[string]interface{}
}

func newRequestIdentityDefinitions(request protocols.Request) (*requestIdentityDefinitions, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	full := make(map[string]interface{})
	if err := json.Unmarshal(encoded, &full); err != nil {
		return nil, err
	}
	projected := make(map[string]interface{}, len(full))
	for key, value := range full {
		projected[key] = value
	}
	projectRequestIdentityDefinition(projected)
	return &requestIdentityDefinitions{fullEncoded: encoded, full: full, projected: projected}, nil
}

func requestBlockIDFromDefinitions(request protocols.Request, definitions *requestIdentityDefinitions, useFullDefinition bool) (string, error) {
	protocol := request.Type().String()
	if id := request.GetID(); id != "" && !useFullDefinition {
		return fmt.Sprintf("%s:%s:explicit:%s", requestBlockIdentityVersion, protocol, id), nil
	}
	if useFullDefinition {
		return fullStructuralRequestBlockIDFromDefinitions(request, definitions), nil
	}
	return structuralRequestBlockIDFromDefinition(request, definitions.projected)
}

func structuralRequestBlockIDFromDefinition(request protocols.Request, definition map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(definition)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("%s:%s:sha256:%x", requestBlockIdentityVersion, request.Type().String(), digest), nil
}

func fullStructuralRequestBlockIDFromDefinitions(request protocols.Request, definitions *requestIdentityDefinitions) string {
	digest := sha256.Sum256(definitions.fullEncoded)
	return fmt.Sprintf("%s:%s:sha256:%x", requestBlockIdentityVersion, request.Type().String(), digest)
}

func requestBlockID(request protocols.Request) (string, error) {
	protocol := request.Type().String()
	if id := request.GetID(); id != "" {
		return fmt.Sprintf("%s:%s:explicit:%s", requestBlockIdentityVersion, protocol, id), nil
	}
	return structuralRequestBlockID(request)
}

func structuralRequestBlockID(request protocols.Request) (string, error) {
	definitions, err := newRequestIdentityDefinitions(request)
	if err != nil {
		return "", err
	}
	return structuralRequestBlockIDFromDefinition(request, definitions.projected)
}

func fullStructuralRequestBlockID(request protocols.Request) (string, error) {
	definitions, err := newRequestIdentityDefinitions(request)
	if err != nil {
		return "", err
	}
	return fullStructuralRequestBlockIDFromDefinitions(request, definitions), nil
}

func projectRequestIdentityDefinition(definition map[string]interface{}) {
	matcherRoles := requestIdentityRoles(definition["matchers"])
	extractorRoles := requestIdentityRoles(definition["extractors"])
	for field := range requestIdentityIgnoredFields {
		delete(definition, field)
	}
	delete(definition, "matchers")
	delete(definition, "extractors")

	if payloads, ok := definition["payloads"].(map[string]interface{}); ok {
		keys := make([]string, 0, len(payloads))
		for key := range payloads {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		definition["payloads"] = keys
	} else {
		delete(definition, "payloads")
	}
	if matcherRoles != nil {
		definition["matcher-roles"] = matcherRoles
	}
	if extractorRoles != nil {
		definition["extractor-roles"] = extractorRoles
	}
}

func requestProbeIDsFromDefinition(request protocols.Request, definition map[string]interface{}) ([]string, error) {
	probeField := ""
	switch request.Type().String() {
	case "http":
		if _, ok := definition["path"]; ok {
			probeField = "path"
		} else if _, ok := definition["raw"]; ok {
			probeField = "raw"
		}
	case "tcp":
		probeField = "host"
	}
	probes, ok := definition[probeField].([]interface{})
	if !ok || len(probes) == 0 {
		return nil, nil
	}

	identities := make([]string, 0, len(probes))
	for _, probe := range probes {
		probeDefinition := make(map[string]interface{}, len(definition))
		for key, value := range definition {
			probeDefinition[key] = value
		}
		probeDefinition[probeField] = []interface{}{probe}
		encoded, err := json.Marshal(probeDefinition)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(encoded)
		identities = append(identities, fmt.Sprintf("%s:%s:probe-sha256:%x", requestBlockIdentityVersion, request.Type().String(), digest))
	}
	return identities, nil
}

func requestIdentityRoles(value interface{}) *requestIdentityOperatorRoles {
	entries, ok := value.([]interface{})
	if !ok || len(entries) == 0 {
		return nil
	}

	roles := &requestIdentityOperatorRoles{}
	named := make(map[requestIdentityOperatorRole]struct{})
	for _, value := range entries {
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		internal, _ := entry["internal"].(bool)
		if internal {
			roles.Internal = true
		} else {
			roles.External = true
		}
		name, _ := entry["name"].(string)
		if name != "" {
			named[requestIdentityOperatorRole{Name: name, Internal: internal}] = struct{}{}
		}
	}
	roles.Named = make([]requestIdentityOperatorRole, 0, len(named))
	for role := range named {
		roles.Named = append(roles.Named, role)
	}
	sort.Slice(roles.Named, func(i, j int) bool {
		if roles.Named[i].Name != roles.Named[j].Name {
			return roles.Named[i].Name < roles.Named[j].Name
		}
		return !roles.Named[i].Internal && roles.Named[j].Internal
	})
	return roles
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
