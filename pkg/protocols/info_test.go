package protocols

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestRenderInfoLeavesStaticInfoAlone(t *testing.T) {
	result := &output.ResultEvent{Host: "example.com", Info: model.Info{Description: "Redis is exposed"}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{"host": "example.com"})

	require.Equal(t, "Redis is exposed", result.Info.Description)
	require.Nil(t, result.TemplateInfo)
}

// Braces that fill nothing, like an SSTI payload in the description, leave the
// text static, so it is neither redacted nor moved off the sarif rule.
func TestRenderInfoLeavesUnfilledBracesStatic(t *testing.T) {
	result := &output.ResultEvent{Host: "example.com", Info: model.Info{Description: "Send {{7*7}} or {{config}} in the name parameter"}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{})

	require.Equal(t, "Send {{7*7}} or {{config}} in the name parameter", result.Info.Description)
	require.Nil(t, result.TemplateInfo)
}

func TestRenderInfoFillsResultAndEventValues(t *testing.T) {
	result := &output.ResultEvent{
		Host:        "example.com",
		Port:        "6379",
		MatcherName: "auth",
		Info: model.Info{
			Name:        "Redis {{version}}",
			Description: "{{matcher-name}} on {{host}}:{{port}}, version {{version}}",
			Impact:      "{{to_upper(password)}}",
			Remediation: "{{credentials}} stays",
		},
	}
	// The event's host is the raw input, while the output reports the hostname.
	data := map[string]interface{}{"host": "redis://example.com:6379", "version": "7.2.4", "password": "admin"}

	renderInfo([]*output.ResultEvent{result}, data)

	require.Equal(t, "auth on example.com:6379, version 7.2.4", result.Info.Description)
	require.Equal(t, "ADMIN", result.Info.Impact)
	require.Equal(t, "{{credentials}} stays", result.Info.Remediation)
	require.Equal(t, "Redis {{version}}", result.Info.Name)
	require.Equal(t, "redis://example.com:6379", data["host"])
	require.NotNil(t, result.TemplateInfo)
	require.Equal(t, "{{matcher-name}} on {{host}}:{{port}}, version {{version}}", result.TemplateInfo.Description)
	require.Equal(t, "{{to_upper(password)}}", result.TemplateInfo.Impact)
}

// Info renders like requests do, so the usual nested placeholder idiom and an
// expression spread over lines work too.
func TestRenderInfoFillsNestedAndMultilinePlaceholders(t *testing.T) {
	result := &output.ResultEvent{Info: model.Info{
		Description: "Authorization: Basic {{base64('{{username}}:{{password}}')}}",
		Remediation: "Upgrade from {{join(\", \",\n  versions)}}",
	}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{
		"username": "admin", "password": "secret", "versions": []string{"7.2.4", "6.0.9"},
	})

	require.Equal(t, "Authorization: Basic YWRtaW46c2VjcmV0", result.Info.Description)
	require.Equal(t, "Upgrade from 7.2.4, 6.0.9", result.Info.Remediation)
}

// A hyphenated name reads as subtraction inside a helper unless it is bracketed,
// and the general §name§ marker fills like a {{name}} one.
func TestRenderInfoFillsBracketedNamesAndGeneralMarkers(t *testing.T) {
	result := &output.ResultEvent{MatcherName: "auth", Info: model.Info{
		Description: "{{to_upper([matcher-name])}} matched",
		Impact:      "default login §username§ accepted",
	}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{"username": "admin"})

	require.Equal(t, "AUTH matched", result.Info.Description)
	require.Equal(t, "default login admin accepted", result.Info.Impact)
}

// A failing expression leaves its field as written; the other fields render.
func TestRenderInfoKeepsAFieldWithAFailingExpression(t *testing.T) {
	result := &output.ResultEvent{Host: "example.com", Info: model.Info{
		Description: "{{host}} {{to_upper(missing)}}",
		Impact:      "{{host}} is exposed",
	}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{})

	require.Equal(t, "{{host}} {{to_upper(missing)}}", result.Info.Description)
	require.Equal(t, "example.com is exposed", result.Info.Impact)
	require.Len(t, result.Info.FilledFields(result.TemplateInfo), 1)
}

// A global matcher's event belongs to the template whose response it matched,
// so only the result fields fill its info.
func TestRenderInfoFillsGlobalMatcherInfoFromResultFieldsOnly(t *testing.T) {
	result := &output.ResultEvent{Host: "example.com", Info: model.Info{Description: "Leaked {{token}} on {{host}}"}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{"global-matchers": true, "token": "origin-template-payload"})

	require.Equal(t, "Leaked {{token}} on example.com", result.Info.Description)
}

// Results are built without scan options, so a network helper never runs.
func TestRenderInfoDeniesNetworkHelpers(t *testing.T) {
	result := &output.ResultEvent{Host: "example.com", Info: model.Info{Description: "{{host}} resolves to {{resolve(host)}}"}}

	renderInfo([]*output.ResultEvent{result}, map[string]interface{}{})

	require.Equal(t, "{{host}} resolves to {{resolve(host)}}", result.Info.Description)
	require.Nil(t, result.TemplateInfo)
}
