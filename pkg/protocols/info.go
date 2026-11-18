package protocols

import (
	"maps"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
)

// renderInfo fills the {{placeholders}} in the free text of each result's info
// with the values of the event that produced it, so a finding can say what was
// found and where. Name, severity, tags and classification stay as written:
// they identify the template for filtering, grouping and issue trackers.
//
// Each result holds its own copy of the info, so the template is never changed.
// When filling changes the text, the result keeps the info as written in
// TemplateInfo.
func renderInfo(results []*output.ResultEvent, data map[string]interface{}) []*output.ResultEvent {
	// A global matcher matches on another template's event, with that template's
	// payloads, variables and extracted values, so only the result fields fill
	// its info.
	if isGlobal, _ := data["global-matchers"].(bool); isGlobal {
		data = nil
	}
	for _, result := range results {
		if !result.Info.HasPlaceholders() {
			continue
		}
		written := result.Info
		values := infoValues(result, data)
		for _, field := range result.Info.PlaceholderFields() {
			if field.HasPlaceholders() {
				*field.Value = renderInfoText(result.TemplateID, *field.Value, values)
			}
		}
		if len(result.Info.FilledFields(&written)) > 0 {
			result.TemplateInfo = &written
		}
	}
	return results
}

// infoValues returns the event data with the result's own fields on top, under
// their names in the JSON output. Those win over the event's keys: in an http
// event host is the raw input URL, while the output reports the hostname.
func infoValues(result *output.ResultEvent, data map[string]interface{}) map[string]interface{} {
	values := make(map[string]interface{}, len(data)+9)
	maps.Copy(values, data)
	for key, value := range map[string]string{
		"host":           result.Host,
		"port":           result.Port,
		"ip":             result.IP,
		"url":            result.URL,
		"scheme":         result.Scheme,
		"path":           result.Path,
		"matched-at":     result.Matched,
		"matcher-name":   result.MatcherName,
		"extractor-name": result.ExtractorName,
	} {
		if value != "" {
			values[key] = value
		}
	}
	return values
}

// renderInfoText renders the text through the shared renderer, as requests and
// matchers are, so nested placeholders and helpers behave the same way. Scan
// options are left out, so network helpers stay denied while results are built.
// If an expression fails, the text stays as written, as a word matcher's does:
// a typo in the template must not cost the finding.
func renderInfoText(templateID, text string, values map[string]interface{}) string {
	rendered, err := render.Render(render.Input{Text: text, Values: values})
	if err != nil {
		gologger.Verbose().Msgf("[%s] Could not render template info: %s\n", templateID, err)
		return text
	}
	return rendered.Text
}
